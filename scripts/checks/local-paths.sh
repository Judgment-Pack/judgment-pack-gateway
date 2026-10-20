#!/usr/bin/env bash
# No machine-local path in tracked text: a /home/<name> or /tmp/<name> path of someone's machine.
# Not counted: the container users' homes (/home/engine, /home/engine-mcp, /home/engine-N), which the
# engine image defines; and the files below, where a /home or /tmp path is the content under test, a
# path inside a container, or a usage hint of a script. A new file is checked.
set -e
if git grep -nP '(^|[^A-Za-z0-9_])/(home/(?!engine)|tmp/)[A-Za-z0-9_.-]+' -- . ':!*.png' ':!*.jpg' \
  ':!.github/test_image_checks.py' \
  ':!scripts/checks/image-root-unwritable.sh' \
  ':!adapters/connections/document_processing_test.go' \
  ':!adapters/websource/adapter_test.go' \
  ':!go/service_test.go' \
  ':!testdata/s3-desk/build-overlay.py' \
  ':!testdata/tool-descriptors/make_pydantic_fixtures.py' \
  ':!testdata/tool-descriptors/make_zod_fixtures.cjs'; then
  echo 'a machine-local path is in tracked text'; exit 1
fi
