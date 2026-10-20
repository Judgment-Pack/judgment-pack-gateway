#!/usr/bin/env bash
# CI step: The runtime evaluates as a platform user and its record cites receipts as given
# The runtime evaluates for whoever runs it, on a project that user
# owns: the image's working directory is the signer's home, which a
# platform user cannot enter, so the project is mounted and named --
# here as uid 65601, HOME and the working directory on the mount --
# and the decision record it appends carries the citations it was
# given, as given, which is what the engine's verify reads.
set -e
mkdir -p project/packs project/audit
cp .github/fixtures/runtime/data-request-intake-triage.json project/packs/intake.json
printf '%s' '{"configVersion":"3","audit":{"dir":"audit"},"packs":{"intake":{"path":"packs/intake.json"}}}' > project/jpack.json
printf '%s' '{"request":{"type":"data-access","completeness":"complete","appropriateness":"hard-fail","embargoedInformationToUnauthorizedRecipients":false}}' > project/facts.json
printf '%s' '{"intake-form":"present","sponsor-endorsement":"present"}' > project/evidence.json
signature=$(printf 'a%.0s' $(seq 128))
printf '[{"sessionId":"s-1","callIndex":0,"signature":"%s"}]' "$signature" > project/cites.json
sudo chown -R 65601:65601 project
docker run --rm --user 65601 -e HOME=/project -w /project -v "$PWD/project:/project" --entrypoint /usr/local/bin/jpack engine:ci \
  experimental evaluate --pack-id intake --facts facts.json --evidence evidence.json --cites cites.json --format json > result.json
# The record is that user's alone (the runtime writes it so);
# the project is handed back to the runner to read it.
sudo chown -R "$(id -u):$(id -g)" project
python3 - "$signature" <<'PY'
import json, sys
# The disposition the fixture's facts reach under this pack: the
# outcome the runtime's own test of the same fixture expects.
result = json.load(open("result.json"))
disposition = result.get("disposition")
assert isinstance(disposition, dict) and disposition.get("kind") == "outcome" and disposition.get("outcomeId") == "decline-redirect", result
lines = [line for line in open("project/audit/evaluations.jsonl").read().split("\n") if line.strip()]
assert len(lines) == 1, lines
# As given means as written: the member's bytes on the record line,
# integer index and all, not a decoded value Python would fold.
expected = '"cites":[{"sessionId":"s-1","callIndex":0,"signature":"%s"}]' % sys.argv[1]
assert expected in lines[0], lines[0]
record = json.loads(lines[0])
assert record.get("kind") == "evaluation" and record.get("recordVersion") == "1", record
print("the record cites what it was given, as given, and the evaluation reached its outcome")
PY
# As built: no entrypoint or command override, so the default CMD is what runs.
docker run --rm engine:ci 2>&1 | grep -q 'engine configuration: open /etc/engine/engine.json' || { echo "the image does not start the engine with its own command"; exit 1; }
