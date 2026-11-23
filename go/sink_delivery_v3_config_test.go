package main

// receiptSink.deliveryVersion "3" and receiptSink.refusalEntries at load
// (ADR-0059 section 9, condition C11): each refusal names the member and
// quotes no value it was given.

import (
	"strings"
	"testing"
)

func parseSinkMember(t *testing.T, text, version string) (*receiptSinkSpec, error) {
	t.Helper()
	v, err := parseJSON([]byte(text))
	if err != nil {
		t.Fatalf("the member is not JSON: %v", err)
	}
	return parseReceiptSink(v, version)
}

func TestDeliveryVersion3IsAVersionedMemberWithItsOwnSwitch(t *testing.T) {
	const url = `"url":"https://sink.example/receipts"`
	if !engineVersions[sinkDeliveryV3Version] || !versionAtLeast(engineVersion, sinkDeliveryV3Version) {
		t.Fatalf("the engine does not read version %s", sinkDeliveryV3Version)
	}
	for _, c := range []struct {
		name, text, version, want string
	}{
		{"deliveryVersion under an earlier version", `{` + url + `,"deliveryVersion":"3"}`, admissionReadV2Version,
			"receiptSink: deliveryVersion is a version-" + sinkDeliveryV3Version + " member; engineVersion " + admissionReadV2Version + " has no deliveryVersion"},
		{"deliveryVersion of another string", `{` + url + `,"deliveryVersion":"three"}`, sinkDeliveryV3Version,
			`receiptSink: deliveryVersion, when present, is the string "3"`},
		{"deliveryVersion 1", `{` + url + `,"deliveryVersion":"1"}`, sinkDeliveryV3Version,
			`receiptSink: deliveryVersion, when present, is the string "3"`},
		{"deliveryVersion 2", `{` + url + `,"deliveryVersion":"2"}`, sinkDeliveryV3Version,
			`receiptSink: deliveryVersion, when present, is the string "3"`},
		{"deliveryVersion as a number", `{` + url + `,"deliveryVersion":3}`, sinkDeliveryV3Version,
			`receiptSink: deliveryVersion, when present, is the string "3"`},
		{"seals true beside 3", `{` + url + `,"deliveryVersion":"3","seals":true}`, sinkDeliveryV3Version,
			`receiptSink: seals is implied by deliveryVersion "3"`},
		{"seals false beside 3", `{` + url + `,"deliveryVersion":"3","seals":false}`, sinkDeliveryV3Version,
			`receiptSink: seals is implied by deliveryVersion "3"`},
		{"refusalEntries without deliveryVersion", `{` + url + `,"refusalEntries":false}`, sinkDeliveryV3Version,
			`receiptSink: refusalEntries is a member of deliveryVersion "3"; a receiptSink without deliveryVersion "3" has no refusalEntries`},
		{"refusalEntries beside seals", `{` + url + `,"seals":true,"refusalEntries":true}`, sinkDeliveryV3Version,
			`receiptSink: refusalEntries is a member of deliveryVersion "3"`},
		{"refusalEntries under an earlier version", `{` + url + `,"refusalEntries":false}`, sealSinkVersion,
			`receiptSink: refusalEntries is a member of deliveryVersion "3"`},
		{"refusalEntries not a boolean", `{` + url + `,"deliveryVersion":"3","refusalEntries":"nope"}`, sinkDeliveryV3Version,
			"receiptSink: refusalEntries, when present, is true or false"},
		{"another member", `{` + url + `,"deliveryVersion":"3","kinds":[]}`, sinkDeliveryV3Version, "kinds"},
	} {
		_, err := parseSinkMember(t, c.text, c.version)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v; want %q", c.name, err, c.want)
			continue
		}
		for _, given := range []string{"three", "nope"} {
			if strings.Contains(c.text, given) && strings.Contains(err.Error(), given) {
				t.Errorf("%s: the refusal quotes the value given: %v", c.name, err)
			}
		}
	}
	for _, c := range []struct {
		name, text                         string
		v3, seals, refusalEntries, payload bool
	}{
		{"no member: as before", `{` + url + `}`, false, false, false, false},
		{"seals alone: as before", `{` + url + `,"seals":true}`, false, true, false, false},
		{"3: seals implied, refusal entries on", `{` + url + `,"deliveryVersion":"3"}`, true, true, true, false},
		{"3 with refusal entries declined", `{` + url + `,"deliveryVersion":"3","refusalEntries":false}`, true, true, false, false},
		{"3 with refusal entries on and the payload", `{` + url + `,"deliveryVersion":"3","refusalEntries":true,"payload":true}`, true, true, true, true},
	} {
		spec, err := parseSinkMember(t, c.text, sinkDeliveryV3Version)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if spec.deliveryV3 != c.v3 || spec.seals != c.seals || spec.refusalEntries != c.refusalEntries || spec.payload != c.payload {
			t.Errorf("%s: %+v", c.name, *spec)
		}
	}
}
