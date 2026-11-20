package main

// gateway retain: the refusals of the acknowledgment file's form, of what
// a store holds that the call could not remove whole, and the run a cut left
// half done (retain.go, chooseRetained and retainFrom).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ackLineMembers is retentionAckLine's line with the member named drop left
// out and, where extra is not empty, a member of that name added, signed over
// what remains, so that only the line's form refuses it.
func ackLineMembers(priv ed25519.PrivateKey, sessionID, sealSignature string, finalCount int64, at, drop, extra string) []byte {
	obj := newObject()
	members := map[string]value{
		"acknowledgedAt": vString(at), "finalCount": vInt(finalCount),
		"keyId": vString(keyIDFor(priv.Public().(ed25519.PublicKey))), "kind": vString(retentionAckKind),
		"sealSignature": vString(sealSignature), "sessionId": vString(sessionID),
	}
	for name, v := range members {
		if name != drop {
			obj.set(name, v)
		}
	}
	if extra != "" {
		obj.set(extra, vInt(1))
	}
	obj.set("signature", vString(hex.EncodeToString(ed25519.Sign(priv, recordSigningInput(retentionAckContext, obj)))))
	return append(canon(obj), '\n')
}

// retainTree is what a refused call must leave as it found it: the store's
// files and the registry's bytes.
func retainTree(t *testing.T, g *gatewayService) (map[string]string, string) {
	t.Helper()
	return storeTree(t, g.storeRoot), readFile(t, g.regPath)
}

func requireRetainUnchanged(t *testing.T, g *gatewayService, tree map[string]string, registry string) {
	t.Helper()
	got, reg := retainTree(t, g)
	if !sameEntries(got, tree) || reg != registry {
		t.Fatal("a refused call changed the store")
	}
	if _, err := os.Stat(filepath.Join(g.storeRoot, removalsFile)); !os.IsNotExist(err) {
		t.Fatalf("a removal file was written: %v", err)
	}
}

// Each way the acknowledgment file can be wrong refuses the whole call, by
// the form it breaks, before anything is written: a line not in canonical
// form, one with a member more or fewer, a session named twice, more lines
// than the bound, a line at the byte bound, a file with no final line feed,
// and a count the seal does not state beside a signature that is right.
// Under --scope, a session of another scope identifier is kept with its
// note.
func TestRetainRefusesWhatTheAcknowledgmentFileGetsWrong(t *testing.T) {
	g, config := retainStore(t)
	a1 := sealOf(t, g.regPath, g.publicKey, "a1")
	sealed := sealTime(t, a1)
	at := stampOf(sealed.Add(time.Hour))
	now := sealed.Add(31 * 24 * time.Hour)
	good := retentionAckLine(retentionAckKey, "a1", a1.signature, a1.finalCount, at)
	const wrongForm = "does not hold exactly an acknowledgment's members"
	cases := []struct {
		name string
		data []byte
		rest []string
		code int
		want string
	}{
		{"a line not canonical", bytes.Replace(good, []byte(`{"acknowledgedAt"`), []byte(`{ "acknowledgedAt"`), 1), nil, 1,
			"retain: acknowledgment line 1 is not one canonical JSON object\n"},
		{"a member more", ackLineMembers(retentionAckKey, "a1", a1.signature, a1.finalCount, at, "", "extra"), nil, 1,
			"retain: acknowledgment line 1 " + wrongForm + "\n"},
		{"a member fewer", ackLineMembers(retentionAckKey, "a1", a1.signature, a1.finalCount, at, "finalCount", ""), nil, 1,
			"retain: acknowledgment line 1 " + wrongForm + "\n"},
		{"a member renamed", ackLineMembers(retentionAckKey, "a1", a1.signature, a1.finalCount, at, "finalCount", "count"), nil, 1,
			"retain: acknowledgment line 1 " + wrongForm + "\n"},
		{"a session named twice", append(append([]byte{}, good...), retentionAckLine(retentionAckKey, "a1", a1.signature, a1.finalCount, stampOf(sealed.Add(2*time.Hour)))...), nil, 1,
			"retain: acknowledgment line 2 names the session line 1 names\n"},
		{"more lines than the bound", bytes.Repeat([]byte("\n"), maxRetentionAckLines+1), nil, 1,
			fmt.Sprintf("retain: the acknowledgments: more than %d lines, and nothing was removed\n", maxRetentionAckLines)},
		{"a line at the byte bound", append(bytes.Repeat([]byte("x"), removalLineBound), '\n'), nil, 1,
			fmt.Sprintf("retain: the acknowledgments: a line is longer than %d bytes, and nothing was removed\n", removalLineBound-1)},
		{"no final line feed", bytes.TrimSuffix(good, []byte("\n")), nil, 1,
			"retain: the acknowledgments: the file does not end with a line feed, and nothing was removed\n"},
		{"a count the seal does not state", retentionAckLine(retentionAckKey, "a1", a1.signature, a1.finalCount+1, at), nil, 1,
			"retain: acknowledgment line 1 names session a1 under another seal than the store holds\n"},
		{"another scope identifier than --scope names", good, []string{"--scope", otherScope}, 0,
			"retain: session a1 is of another scope identifier than --scope names; it is kept\n"},
	}
	tree, registry := retainTree(t, g)
	for _, tc := range cases {
		path := filepath.Join(t.TempDir(), "acks.jsonl")
		if err := os.WriteFile(path, tc.data, 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := runRetain(config, path, now, tc.rest...)
		if code != tc.code || stdout != "" || !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: %d %q %q", tc.name, code, stdout, stderr)
		}
		if tc.code == 1 && !strings.Contains(stderr, "retain: nothing was removed\n") && !strings.Contains(stderr, "and nothing was removed\n") {
			t.Errorf("%s: it does not say nothing was removed: %q", tc.name, stderr)
		}
		requireRetainUnchanged(t, g, tree, registry)
	}
}

// A line that fits to 4,095 bytes is read, and refused by its form: the
// byte bound is where the reader stops, not where the form does.
func TestRetainReadsALineOfTheLargestSize(t *testing.T) {
	g, config := retainStore(t)
	a1 := sealOf(t, g.regPath, g.publicKey, "a1")
	line := append(bytes.Repeat([]byte("x"), removalLineBound-1), '\n')
	code, stdout, stderr := runRetain(config, writeAcks(t, line), sealTime(t, a1).Add(31*24*time.Hour))
	if code != 1 || stdout != "" || !strings.Contains(stderr, "retain: acknowledgment line 1 is not canonical JSON\n") {
		t.Fatalf("%d %q %q", code, stdout, stderr)
	}
}

// A session whose receipts carry more than one scope identifier, and a
// receipt left in the store that cites a receipt the call would remove,
// refuse the call by name, and the store is as it was.
func TestRetainRefusesASessionItCannotRemoveWhole(t *testing.T) {
	vector := readStoreVector(t, "v3-action-remote-transport-valid")
	action := vector.Files["receipts/s2/1.json"]
	for _, tc := range []struct {
		name  string
		extra [][3]string
		setup func(t *testing.T, g *gatewayService)
		want  string
	}{
		{"receipts of two scope identifiers", [][3]string{{"a1", "b", "mixed-b"}}, func(*testing.T, *gatewayService) {},
			"retain: acknowledgment line 1 names session a1, which holds receipts of more than one scope identifier, of none, or not verifying; the session is left whole\n"},
		{"a receipt citing a receipt it would remove", nil, func(t *testing.T, g *gatewayService) {
			planted := strings.Replace(action, `"sessionId":"s2","signature"`, `"sessionId":"a1","signature"`, 1)
			writeStoreFile(t, g, "receipts/c/1.json", strings.ReplaceAll(planted, vectorKeyID(t, action), g.keyID))
		}, "retain: receipt c/1 cites receipt a1/0, of session a1, which the call would remove; its citation would no longer resolve\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, config := retainStore(t, tc.extra...)
			tc.setup(t, g)
			a1 := sealOf(t, g.regPath, g.publicKey, "a1")
			acks := writeAcks(t, retentionAckLine(retentionAckKey, "a1", a1.signature, a1.finalCount, stampOf(sealTime(t, a1))))
			tree, registry := retainTree(t, g)
			code, stdout, stderr := runRetain(config, acks, sealTime(t, a1).Add(31*24*time.Hour))
			if code != 1 || stdout != "" || !strings.Contains(stderr, tc.want) || !strings.Contains(stderr, "retain: nothing was removed\n") {
				t.Fatalf("%d %q %q", code, stdout, stderr)
			}
			requireRetainUnchanged(t, g, tree, registry)
		})
	}
}

// A session the registry holds two seals for -- an ordinary seal and one
// made after an interruption -- is refused by name, though the
// acknowledgment names the seal the walk anchors it by.
func TestRetainRefusesASessionWhoseSealIsInConflict(t *testing.T) {
	g, config := retainStore(t)
	a1 := sealOf(t, g.regPath, g.publicKey, "a1")
	head := receiptSignature(t, g.storeRoot, "a1", int(a1.finalCount)-1)
	appendRegistry(t, g.regPath, interruptionSealLineBy(ed25519.NewKeyFromSeed(testSeed), g.keyID, "a1", a1.finalCount, head, a1.sealedAt, "command"))
	acks := writeAcks(t, retentionAckLine(retentionAckKey, "a1", a1.signature, a1.finalCount, stampOf(sealTime(t, a1))))
	tree, registry := retainTree(t, g)
	code, stdout, stderr := runRetain(config, acks, sealTime(t, a1).Add(31*24*time.Hour))
	want := "retain: acknowledgment line 1 names session a1, for which the registry holds more than one seal (SPEC.md §3c); a session whose seal is in conflict is never removed\n"
	if code != 1 || stdout != "" || !strings.Contains(stderr, want) || !strings.Contains(stderr, "retain: nothing was removed\n") {
		t.Fatalf("%d %q %q", code, stdout, stderr)
	}
	requireRetainUnchanged(t, g, tree, registry)
}

// A run cut off after its records were appended and before its files went
// leaves a session recorded as removed whose files remain; a second run with
// the same acknowledgments removes them and signs nothing again, and the
// store verifies. The session's directory left empty is finished the same.
func TestRetainFinishesARemovalARunCutOffAfterItsRecord(t *testing.T) {
	for _, tc := range []struct {
		name    string
		receipt bool
	}{{"receipts left", true}, {"an empty directory left", false}} {
		t.Run(tc.name, func(t *testing.T) {
			g, config := retainStore(t)
			a1 := sealOf(t, g.regPath, g.publicKey, "a1")
			now := sealTime(t, a1).Add(31 * 24 * time.Hour)
			acks := writeAcks(t, retentionAckLine(retentionAckKey, "a1", a1.signature, a1.finalCount, stampOf(sealTime(t, a1).Add(time.Hour))))
			dir := filepath.Join(g.storeRoot, "receipts", "a1")
			held := map[string][]byte{}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) == 0 {
				t.Fatalf("a1: %v", err)
			}
			for _, e := range entries {
				data, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				held[e.Name()] = data
			}
			payloads := map[string][]byte{}
			artifacts, _ := os.ReadDir(filepath.Join(g.storeRoot, "artifacts"))
			for _, e := range artifacts {
				data, err := os.ReadFile(filepath.Join(g.storeRoot, "artifacts", e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				payloads[e.Name()] = data
			}

			if code, _, stderr := runRetain(config, acks, now); code != 0 {
				t.Fatalf("the first run: %d %q", code, stderr)
			}
			record := readFile(t, filepath.Join(g.storeRoot, removalsFile))
			// payloads the first run kept are shared with a session that stays
			kept := storeTree(t, filepath.Join(g.storeRoot, "artifacts"))
			// the state the cut leaves: the record there, the files not gone
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.receipt {
				for name, data := range held {
					if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				for name, data := range payloads {
					if err := os.WriteFile(filepath.Join(g.storeRoot, "artifacts", name), data, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}

			code, stdout, stderr := runRetain(config, acks, now)
			if code != 0 || stdout != "" || !strings.Contains(stderr, "retain: session a1 was recorded as removed already; its files, still there, are removed now\n") {
				t.Fatalf("the second run: %d %q %q", code, stdout, stderr)
			}
			if readFile(t, filepath.Join(g.storeRoot, removalsFile)) != record {
				t.Fatal("the second run changed the removal file")
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("a1 is still there: %v", err)
			}
			if !sameEntries(storeTree(t, filepath.Join(g.storeRoot, "artifacts")), kept) {
				t.Fatal("the payloads the first run removed are there, or the payloads it kept are not")
			}
			_, findings, observations := scopeVerdict(t, g)
			if strings.Join(findings, ",") != "a2 unregistered-session" || !strings.Contains(strings.Join(observations, ","), "a1 "+observationSessionRemoved) {
				t.Fatalf("the verdict: %v %v", findings, observations)
			}
			if code, stdout, stderr = runRetain(config, acks, now); code != 0 || stdout != "" || !strings.Contains(stderr, "retain: session a1 was recorded as removed already\n") {
				t.Fatalf("a third run: %d %q %q", code, stdout, stderr)
			}
		})
	}
}

// A store rotated away from is refused by the rotation's sentence before
// anything is written: a removal appended to its registry would break the
// link the new store names (ADR-0048), so a line that would otherwise
// remove a1 removes nothing.
func TestRetainRefusesAStoreRotatedAwayFrom(t *testing.T) {
	g, config := retainStore(t)
	a1 := sealOf(t, g.regPath, g.publicKey, "a1")
	acks := writeAcks(t, retentionAckLine(retentionAckKey, "a1", a1.signature, a1.finalCount, stampOf(sealTime(t, a1))))
	if err := os.WriteFile(rotatedMarkPath(g.regPath), []byte(rotatedMarkPrefix+strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tree, registry := retainTree(t, g)
	code, stdout, stderr := runRetain(config, acks, sealTime(t, a1).Add(31*24*time.Hour))
	if code != 1 || stdout != "" || !strings.Contains(stderr, "the store was rotated away from ("+rotatedMarkPrefix+strings.Repeat("ab", 32)+")") {
		t.Fatalf("%d %q %q", code, stdout, stderr)
	}
	requireRetainUnchanged(t, g, tree, registry)
}
