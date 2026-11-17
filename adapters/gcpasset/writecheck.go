package gcpasset

// The write check (decision 3, Amendment A2): for each configured project,
// projects.testIamPermissions with a fixed list of write permissions, in
// calls of at most 100, with the check token alone. A grant of any refuses,
// naming the first granted in the list's order; a call that fails refuses
// as a grant does. It runs whenever a token is obtained: at the gateway's
// start and at every refresh, before the new token is used.
//
// The projects are asked at most maxConcurrentChecks at a time, so a
// configuration of many projects is checked in a few round trips rather
// than one per project. A check the run's own time (or a cancellation)
// ended before it completed is neither a refusal nor a pass: nothing the
// platform answered shows the credential can write, and no token is sealed
// or used on it (errCheckIncomplete).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sync"

	"adapters/internal/canon"
)

// WriteListVersion names the write list below; it changes whenever the
// list does, and is revisited when the asset types served change and on
// each release of this adapter.
const WriteListVersion = "gcp-asset-write-list/2"

// maxPermissionsPerCall is the platform's bound on one testIamPermissions
// call.
const maxPermissionsPerCall = 100

// maxConcurrentChecks bounds how many projects the write check asks at
// once: maxParents projects take maxParents/maxConcurrentChecks round trips.
const maxConcurrentChecks = 8

// errCheckIncomplete is a read-only check that the run's own time, or a
// cancellation, ended before it completed. It is not a refusal, since
// nothing the platform answered shows the credential can write, and not a
// pass, since no token is sealed or used on it: the command exits 1, and
// the gateway fails that start or that refresh without closing the source,
// which checks again with the next token it asks for.
var errCheckIncomplete = errors.New("the read-only check did not complete within the run's time; no token was sealed or used, and the check runs again with the next token")

// writeList is every write permission the check asks about, in the order a
// refusal names the first one granted. The adapter's README lists it. It is
// a fixed list, not a proof that a credential cannot write: a permission
// outside it is not checked, so the read-only role on the source's own
// principal stays the primary control.
var writeList = []string{
	"resourcemanager.projects.setIamPolicy",
	"resourcemanager.projects.update",
	"resourcemanager.projects.delete",
	"run.services.create",
	"run.services.update",
	"run.services.delete",
	"run.services.setIamPolicy",
	"secretmanager.secrets.create",
	"secretmanager.secrets.update",
	"secretmanager.secrets.delete",
	"secretmanager.secrets.setIamPolicy",
	"secretmanager.versions.add",
	"secretmanager.versions.enable",
	"secretmanager.versions.disable",
	"secretmanager.versions.destroy",
	"iam.serviceAccounts.create",
	"iam.serviceAccounts.update",
	"iam.serviceAccounts.delete",
	"iam.serviceAccounts.setIamPolicy",
	"iam.serviceAccounts.actAs",
	"iam.serviceAccounts.getAccessToken",
	"iam.serviceAccountKeys.create",
	"iam.roles.create",
	"iam.roles.update",
	"iam.roles.delete",
	"storage.buckets.create",
	"storage.buckets.update",
	"storage.buckets.delete",
	"storage.buckets.setIamPolicy",
	"storage.objects.create",
	"storage.objects.delete",
	"cloudasset.feeds.create",
	"cloudasset.feeds.update",
	"cloudasset.feeds.delete",
	"cloudasset.savedqueries.create",
	"cloudasset.savedqueries.update",
	"cloudasset.savedqueries.delete",
	"iam.serviceAccounts.signBlob",
	"iam.serviceAccounts.signJwt",
	"iam.serviceAccounts.implicitDelegation",
	"iam.serviceAccounts.getOpenIdToken",
	"iam.serviceAccountKeys.delete",
	"storage.objects.update",
	"storage.objects.setIamPolicy",
	"run.jobs.create",
	"run.jobs.update",
	"run.jobs.delete",
	"run.jobs.run",
	"run.jobs.setIamPolicy",
	"compute.instances.create",
	"compute.instances.delete",
	"compute.instances.setMetadata",
	"compute.instances.setServiceAccount",
	"compute.projects.setCommonInstanceMetadata",
	"compute.firewalls.create",
	"compute.firewalls.update",
	"compute.firewalls.delete",
	"cloudfunctions.functions.create",
	"cloudfunctions.functions.update",
	"cloudfunctions.functions.delete",
	"cloudfunctions.functions.setIamPolicy",
	"cloudbuild.builds.create",
	"serviceusage.services.enable",
	"serviceusage.services.disable",
	"orgpolicy.policy.set",
	"container.pods.create",
	"artifactregistry.repositories.uploadArtifacts",
	"deploymentmanager.deployments.create",
	"iam.workloadIdentityPoolProviders.create",
	"iam.workloadIdentityPoolProviders.update",
	"cloudkms.cryptoKeyVersions.destroy",
	"logging.sinks.create",
	"cloudscheduler.jobs.create",
	"appengine.versions.create",
	"composer.environments.create",
	"dataflow.jobs.create",
	"cloudsql.instances.update",
	"pubsub.topics.publish",
	"bigquery.tables.updateData",
}

// WriteList is a copy of the write list, for the README's test.
func WriteList() []string { return append([]string(nil), writeList...) }

// batches splits list into consecutive calls of at most size.
func batches(list []string, size int) [][]string {
	var out [][]string
	for len(list) > size {
		out = append(out, list[:size])
		list = list[size:]
	}
	if len(list) > 0 {
		out = append(out, list)
	}
	return out
}

// writeCheck asks about list on every configured project, in calls of at
// most maxPermissionsPerCall, at most maxConcurrentChecks projects at once.
// Read in the configured order, the first project that grants any refuses,
// naming the first granted in list's order, and so does the first whose
// call failed; failing either, a project whose calls the run's time ended
// makes the check incomplete (errCheckIncomplete), never a pass.
func (s *source) writeCheck(ctx context.Context, token string, list []string) error {
	outcomes := make([]error, len(s.cfg.Parents))
	slots := make(chan struct{}, maxConcurrentChecks)
	var wg sync.WaitGroup
	for i, parent := range s.cfg.Parents {
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-slots; wg.Done() }()
			outcomes[i] = s.checkProject(ctx, token, parent, list)
		}()
	}
	wg.Wait()
	incomplete := false
	for _, err := range outcomes {
		switch {
		case errors.Is(err, errCheckIncomplete):
			incomplete = true
		case err != nil:
			return err
		}
	}
	if incomplete {
		return errCheckIncomplete
	}
	return nil
}

// checkProject is the write check on one project: nil where none of list is
// granted; a refusal naming the first granted in list's order, or naming
// none for a call that failed; errCheckIncomplete for a call the run's time
// or a cancellation ended.
func (s *source) checkProject(ctx context.Context, token, parent string, list []string) error {
	granted := map[string]bool{}
	for _, batch := range batches(list, maxPermissionsPerCall) {
		answer, ok := s.testPermissions(ctx, token, parent, batch)
		if !ok {
			if ctx.Err() != nil {
				return errCheckIncomplete
			}
			return &Refused{Reason: ReasonCanWrite}
		}
		for _, p := range answer {
			granted[p] = true
		}
	}
	for _, p := range list {
		if granted[p] {
			return refused(ReasonCanWrite, p)
		}
	}
	return nil
}

// testPermissions is one testIamPermissions call: 200, JSON in the
// canonical domain within 64 KiB, its permissions (absent when none is
// granted) an array of strings each among those asked. Anything else is a
// failed call.
func (s *source) testPermissions(ctx context.Context, token, parent string, asked []string) ([]string, bool) {
	body, err := json.Marshal(map[string][]string{"permissions": asked})
	if err != nil {
		return nil, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoints.ResourceManager+"/v3/"+parent+":testIamPermissions", bytes.NewReader(body))
	if err != nil {
		return nil, false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "judgment-pack-"+adapterName+"/"+Version)
	resp, err := s.api.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenAnswer+1))
	if err != nil || len(raw) > maxTokenAnswer || resp.StatusCode != http.StatusOK {
		return nil, false
	}
	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType != "application/json" {
		return nil, false
	}
	if _, err := canon.Canonicalize(raw, canon.CarryNumbersAsText); err != nil {
		return nil, false
	}
	answer, ok := object(raw)
	if !ok {
		return nil, false
	}
	if _, present := answer["permissions"]; !present {
		// The platform answers {} when it grants none; any other shape
		// without the member is not an answer the check can read.
		if len(answer) != 0 {
			return nil, false
		}
		return nil, true
	}
	list, ok := array(answer["permissions"])
	if !ok {
		return nil, false
	}
	granted := make([]string, 0, len(list))
	for _, item := range list {
		var p string
		if !stringMember(item, &p) || !contains(asked, p) {
			return nil, false
		}
		granted = append(granted, p)
	}
	return granted, true
}
