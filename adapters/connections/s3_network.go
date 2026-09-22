package connections

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/encoding/httpbinding"
)

const s3EmptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Standard commercial-region S3 only. No arbitrary endpoints, redirects,
// environment credentials, metadata service, proxies or credential subprocesses.
func s3URL(c s3Config, key string, q url.Values) (*url.URL, error) {
	if !s3Region.MatchString(c.Region) || !s3Bucket.MatchString(c.Bucket) {
		return nil, ErrRequest
	}
	name := "/" + c.Bucket + "/" + key
	return &url.URL{Scheme: "https", Host: "s3." + c.Region + ".amazonaws.com", Path: name, RawPath: httpbinding.EscapePath(name, false), RawQuery: strings.ReplaceAll(q.Encode(), "+", "%20")}, nil
}
func (p provider) s3Request(ctx context.Context, c s3Config, method, key string, q url.Values, etag string, maxBytes int64) ([]byte, http.Header, error) {
	if c.expired() {
		return nil, nil, Error("credentials-required")
	}
	endpoint, err := s3URL(c, key, q)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), nil)
	if err != nil {
		return nil, nil, ErrRequest
	}
	req.Header.Set("X-Amz-Content-Sha256", s3EmptyHash)
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	err = signer.SignHTTP(ctx, aws.Credentials{AccessKeyID: c.AccessKey, SecretAccessKey: c.SecretKey, SessionToken: c.SessionToken}, req, s3EmptyHash, "s3", c.Region, time.Now())
	if err != nil {
		return nil, nil, ErrProvider
	}
	response, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ErrCanceled
		}
		return nil, nil, ErrProvider
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// Decode only the bounded provider error code; no provider messages/headers
		// or SDK diagnostics are exposed to Desk or the receipt process.
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 16<<10))
		var failure struct {
			Code string `xml:"Code"`
		}
		_ = xml.Unmarshal(raw, &failure)
		switch failure.Code {
		case "ExpiredToken", "InvalidToken", "InvalidAccessKeyId", "SignatureDoesNotMatch", "TokenRefreshRequired":
			return nil, nil, Error("credentials-required")
		case "InvalidObjectState":
			return nil, nil, Error("archived")
		case "AccessDenied", "AllAccessDisabled":
			return nil, nil, Error("permission-required")
		case "SlowDown", "Throttling":
			return nil, nil, Error("rate-limited")
		}
		switch response.StatusCode {
		case 401:
			return nil, nil, Error("credentials-required")
		case 403:
			return nil, nil, Error("permission-required")
		case 404, 412:
			return nil, nil, ErrChanged
		case 429, 503:
			return nil, nil, Error("rate-limited")
		}
		return nil, nil, ErrProvider
	}
	if method == "HEAD" {
		return nil, response.Header, nil
	}
	if response.ContentLength > maxBytes {
		return nil, nil, ErrLimit
	}
	if response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return nil, nil, ErrUnsupported
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, nil, ErrProvider
	}
	if int64(len(raw)) > maxBytes {
		return nil, nil, ErrLimit
	}
	if c.leaks(raw) {
		return nil, nil, ErrProvider
	}
	return raw, response.Header, nil
}
func validS3ETag(etag string) bool {
	if len(etag) < 3 || len(etag) > 256 || etag[0] != '"' || etag[len(etag)-1] != '"' {
		return false
	}
	for _, r := range etag[1 : len(etag)-1] {
		if r < 33 || r > 126 || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}
func (p provider) s3List(ctx context.Context, c s3Config, prefix, token, after string, count int) ([]s3Object, string, error) {
	q := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {strconv.Itoa(count)}, "encoding-type": {"url"}}
	if token != "" {
		q.Set("continuation-token", token)
	}
	if after != "" {
		q.Set("start-after", after)
	}
	raw, _, err := p.s3Request(ctx, c, "GET", "", q, "", 256<<10)
	if err != nil {
		return nil, "", err
	}
	var result struct {
		XMLName   xml.Name `xml:"ListBucketResult"`
		Name      string   `xml:"Name"`
		Encoding  string   `xml:"EncodingType"`
		Prefix    string   `xml:"Prefix"`
		Truncated bool     `xml:"IsTruncated"`
		Next      string   `xml:"NextContinuationToken"`
		Contents  []struct {
			Key     string `xml:"Key"`
			ETag    string `xml:"ETag"`
			Size    *int64 `xml:"Size"`
			Storage string `xml:"StorageClass"`
		} `xml:"Contents"`
	}
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	if dec.Decode(&result) != nil {
		return nil, "", ErrProvider
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, "", ErrProvider
	}
	decodedPrefix, e := url.PathUnescape(result.Prefix)
	if e != nil || result.Name != c.Bucket || result.Encoding != "url" || decodedPrefix != prefix || len(result.Contents) > count || result.Truncated != (result.Next != "") || !resourceText(result.Next, 4096, true) || c.leaks([]byte(result.Next)) {
		return nil, "", ErrProvider
	}
	out := []s3Object{}
	previous := after
	seen := map[string]bool{}
	for _, entry := range result.Contents {
		key, e := url.PathUnescape(entry.Key)
		if e != nil || !resourceText(key, 1024, false) || !strings.HasPrefix(key, prefix) || seen[key] || key <= previous || !validS3ETag(entry.ETag) || entry.Size == nil || *entry.Size < 0 || *entry.Size > 9007199254740991 || !resourceText(entry.Storage, 64, true) || c.leaks([]byte(key+entry.ETag+entry.Storage)) {
			return nil, "", ErrProvider
		}
		seen[key] = true
		previous = key
		out = append(out, s3Object{Key: key, ETag: entry.ETag, Size: *entry.Size, StorageClass: entry.Storage})
	}
	return out, result.Next, nil
}
func s3HeadMeta(headers http.Header, obj s3Object) (s3Object, error) {
	size, err := strconv.ParseInt(headers.Get("Content-Length"), 10, 64)
	if err != nil || size != obj.Size || headers.Get("ETag") != obj.ETag {
		return obj, ErrChanged
	}
	if size > MaxFileBytes {
		return obj, ErrLimit
	}
	obj.StorageClass = headers.Get("X-Amz-Storage-Class")
	if reason := obj.unavailable(); reason != "" {
		return obj, Error(reason)
	}
	if headers.Get("X-Amz-Server-Side-Encryption-Customer-Algorithm") != "" {
		return obj, Error("permission-required")
	}
	version := headers.Get("X-Amz-Version-Id")
	if !resourceText(version, 1024, true) {
		return obj, ErrProvider
	}
	obj.Version = version
	return obj, nil
}
func (p provider) s3Head(ctx context.Context, c s3Config, obj s3Object) (s3Object, error) {
	_, headers, err := p.s3Request(ctx, c, "HEAD", obj.Key, nil, obj.ETag, 0)
	if err != nil {
		return obj, err
	}
	obj, err = s3HeadMeta(headers, obj)
	if err != nil {
		return obj, err
	}
	if c.leaks([]byte(obj.Version)) {
		return obj, ErrProvider
	}
	return obj, nil
}
func (p provider) s3Get(ctx context.Context, c s3Config, obj s3Object) ([]byte, error) {
	if !resourceText(obj.Key, 1024, false) || !strings.HasPrefix(obj.Key, c.Prefix) || !validS3ETag(obj.ETag) || obj.Size <= 0 || obj.Size > MaxFileBytes {
		return nil, ErrGrant
	}
	q := url.Values{}
	if obj.Version != "" {
		q.Set("versionId", obj.Version)
	}
	raw, headers, err := p.s3Request(ctx, c, "GET", obj.Key, q, obj.ETag, MaxFileBytes)
	if err != nil {
		return nil, err
	}
	checked, err := s3HeadMeta(headers, obj)
	if err != nil {
		return nil, err
	}
	if checked.Version != obj.Version || int64(len(raw)) != obj.Size {
		return nil, ErrChanged
	}
	return raw, nil
}
