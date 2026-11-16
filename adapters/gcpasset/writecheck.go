package gcpasset

// The write check (decision 3, Amendment A2): for each configured project,
// projects.testIamPermissions with a fixed list of write permissions, in
// calls of at most 100, with the check token alone. A grant of any refuses,
// naming the first granted in the list's order; a call that fails refuses
// as a grant does. It runs whenever a token is obtained: at the gateway's
// start and at every refresh, before the new token is used.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"

	"adapters/internal/canon"
)

// WriteListVersion names the write list below; it changes whenever the
// list does, and is revisited when the asset types served change and on
// each release of this adapter.
const WriteListVersion = "gcp-asset-write-list/2"

// maxPermissionsPerCall is the platform's bound on one testIamPermissions
// call.
const maxPermissionsPerCall = 100

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
// most maxPermissionsPerCall, and refuses on the first project that grants
// any, naming the first granted in list's order, or on any call that
// fails.
func (s *source) writeCheck(ctx context.Context, token string, list []string) error {
	for _, parent := range s.cfg.Parents {
		granted := map[string]bool{}
		for _, batch := range batches(list, maxPermissionsPerCall) {
			answer, ok := s.testPermissions(ctx, token, parent, batch)
			if !ok {
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
