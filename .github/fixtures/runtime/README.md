# Runtime fixtures for the image check

`data-request-intake-triage.json` is the runtime repository's own evaluation fixture
(`internal/evaluation/testdata/data-request-intake-triage.json` in
[judgment-pack-runtime](https://github.com/Judgment-Pack/judgment-pack-runtime), Apache-2.0),
copied byte for byte: a synthetic intake-triage pack under JPS Core 0.2.0-draft. The CI image
job evaluates it, as a platform user, with the runtime the engine image carries, and holds the
decision record it writes to the citations it was given. It is a fixture of the check and not
part of the image.
