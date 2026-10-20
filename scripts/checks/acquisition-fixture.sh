#!/usr/bin/env bash
# CI step: Tagged acquisition fixture contracts and refusal checks
set -e
export GOWORK=off
go test -race -tags gateway_acquisition_fixture ./internal/acquisitionfixture ./websource ./connections ./testdata/acquisition-fixture -run '^Test(Fixture|AcquisitionFixture)' -count=1
go vet -tags gateway_acquisition_fixture ./internal/acquisitionfixture ./websource ./connections ./testdata/acquisition-fixture
PYTHONDONTWRITEBYTECODE=1 python3 testdata/acquisition-fixture/build_test.py
PYTHONDONTWRITEBYTECODE=1 python3 testdata/acquisition-fixture/smoke_test.py
