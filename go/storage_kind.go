package main

// The storage member (engineVersion 24, docs/adr/0032-a-configuration-names-its-storage-kind.md):
// the kind that keeps the store and the seal registry. Without it the
// filesystem kind keeps them at store and registry, as before the member;
// with it naming the PostgreSQL kind (store_pg.go, docs/postgresql-store.md)
// the configuration names no store and no registry path, and the kind's
// connection string is named by reference alone -- a file held as the
// seed's file is, or an environment variable -- and never written in the
// configuration, a message, a description or a receipt.
//
// What reads the filesystem store directly, and not through the store
// contract, is not available with the PostgreSQL kind yet: each is refused
// by name (errStorageKindUnsupported), at the configuration's load where the
// configuration asks for it and at the command or the request otherwise, so
// none reads an empty directory in the kind's place.

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

const storagePostgreSQL = "postgresql"

// storageSpec is the storage member as read.
type storageSpec struct {
	kind string
	// file is the absolute path of the file that holds the connection
	// string, or "" when environment names it.
	file string
	// environment is the name of the variable that holds it, or "".
	environment string
	connections int
	operation   time.Duration
}

var storageMembers = map[string]bool{"kind": true, "connection": true, "connections": false, "operationSeconds": false}

// storageEnvironmentName is the form of a variable's name the member takes:
// what every shell and platform reads as one.
var storageEnvironmentName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// errStorageKindUnsupported is every refusal of a command, a member or a
// request that reads the filesystem store directly while the PostgreSQL
// kind keeps it.
var errStorageKindUnsupported = errors.New("storage-kind-unsupported")

func storageUnsupported(what string) error {
	return fmt.Errorf("%w: %s is not available with the PostgreSQL storage kind yet (docs/postgresql-store.md, \"Not available with this kind yet\")", errStorageKindUnsupported, what)
}

// parseStorage reads the storage member.
func parseStorage(v value, version string) (*storageSpec, error) {
	if !versionAtLeast(version, "24") {
		return nil, fmt.Errorf("storage is a version-24 member; engineVersion %s has no storage", version)
	}
	obj, err := requireObject(v, "storage")
	if err != nil {
		return nil, err
	}
	if err := exactlyMembers(obj, storageMembers, "storage"); err != nil {
		return nil, err
	}
	kind, err := requireString(obj, "kind")
	if err != nil || kind != storagePostgreSQL {
		return nil, fmt.Errorf("storage.kind is %q; without storage the filesystem kind keeps the store at store and registry", storagePostgreSQL)
	}
	spec := &storageSpec{kind: kind, connections: pgDefaultConnections, operation: pgDefaultOperation}
	connectionValue, _ := obj.get("connection")
	connection, err := requireObject(connectionValue, "storage.connection")
	if err != nil {
		return nil, err
	}
	if err := exactlyMembers(connection, map[string]bool{"file": false, "environment": false}, "storage.connection"); err != nil {
		return nil, err
	}
	_, byFile := connection.get("file")
	_, byEnvironment := connection.get("environment")
	switch {
	case byFile == byEnvironment:
		return nil, errors.New("storage.connection names the connection string by one reference: file, an absolute path, or environment, a variable's name")
	case byFile:
		if spec.file, err = requireAbsolutePath(connection, "file"); err != nil {
			return nil, fmt.Errorf("storage.connection.%v", err)
		}
	default:
		name, err := requireString(connection, "environment")
		if err != nil || !storageEnvironmentName.MatchString(name) {
			return nil, errors.New("storage.connection.environment is a variable's name: capital letters, digits and _, not starting with a digit, at most 128")
		}
		spec.environment = name
	}
	if n, present, err := integerMember(obj, "connections"); err != nil {
		return nil, errors.New("storage.connections must be an integer")
	} else if present {
		if n < 1 || n > pgMaxConnections {
			return nil, fmt.Errorf("storage.connections %d is outside 1 to %d", n, pgMaxConnections)
		}
		spec.connections = int(n)
	}
	if n, present, err := integerMember(obj, "operationSeconds"); err != nil {
		return nil, errors.New("storage.operationSeconds must be an integer")
	} else if present {
		if n < 1 || n > 600 {
			return nil, fmt.Errorf("storage.operationSeconds %d is outside 1 to 600", n)
		}
		spec.operation = time.Duration(n) * time.Second
	}
	return spec, nil
}

// storageRefusals refuses, at the configuration's load, what the
// configuration asks for that reads the filesystem store directly, while
// the PostgreSQL kind keeps it. (A source's environment is its HOME, the
// platform's own name=value pairs and PATH (deriveSources): it never takes
// the connection string's variable from the engine's, which the start
// removes besides.)
func storageRefusals(cfg *engineConfig) error {
	if cfg.storage == nil {
		return nil
	}
	if cfg.witness != nil {
		return storageUnsupported("witness, which keeps its files beside the registry on disk,")
	}
	if cfg.sealOpenAtStart {
		return storageUnsupported("sealOpenAtStart, which reads the sessions on disk,")
	}
	for _, p := range cfg.platforms {
		switch {
		case p.write:
			return storageUnsupported(fmt.Sprintf("platform %s's write: true, whose actions keep their journal and evidence on disk,", p.name))
		case len(p.descriptorStatements) > 0:
			return storageUnsupported(fmt.Sprintf("platform %s's descriptorStatements, whose snapshot is read from the store on disk,", p.name))
		case p.scope != "":
			return storageUnsupported(fmt.Sprintf("platform %s's scope, since the kind is served as the view of no scope,", p.name))
		}
	}
	return nil
}

// refuseUnderPostgreSQL is a command's refusal of a configuration whose
// store the PostgreSQL kind keeps, for a command that reads the
// filesystem store directly.
func refuseUnderPostgreSQL(cfg engineConfig, command string) error {
	if cfg.storage == nil {
		return nil
	}
	return storageUnsupported(command)
}

// connectCaptureUnsupported names a descriptor capture in its refusal.
const connectCaptureUnsupported = "a descriptor capture, whose snapshot the store on disk keeps (gateway connect --no-descriptors connects a platform without one),"

// storageConnection reads the connection string the member names and parses
// it. Nothing of the string is in an error: a parse that fails says so in a
// fixed sentence (errPgDSN). A variable read is removed from this process's
// environment, so nothing the gateway starts inherits it.
func storageConnection(spec *storageSpec) (pgDSN, error) {
	var text string
	if spec.file != "" {
		raw, err := openSeed(spec.file)
		if err != nil {
			return pgDSN{}, fmt.Errorf("storage.connection.file %s is held as the seed's file is: %v", spec.file, err)
		}
		if len(raw) > maxSeedFileBytes {
			return pgDSN{}, fmt.Errorf("storage.connection.file %s is larger than %d bytes", spec.file, maxSeedFileBytes)
		}
		text = string(raw)
	} else {
		value, present := os.LookupEnv(spec.environment)
		if !present || value == "" {
			return pgDSN{}, fmt.Errorf("storage.connection.environment names %s, which is not set", spec.environment)
		}
		text = value
		if err := os.Unsetenv(spec.environment); err != nil {
			return pgDSN{}, fmt.Errorf("storage.connection.environment: %s could not be removed from the environment", spec.environment)
		}
	}
	d, err := parsePgDSN(strings.TrimSpace(text))
	if err != nil {
		return pgDSN{}, fmt.Errorf("storage.connection: %w", err)
	}
	return d, nil
}

// openStorageKind opens the PostgreSQL kind the member names, held to its
// conditions at its start (pgKind.holdsItsConditions).
func openStorageKind(spec *storageSpec) (*pgKind, error) {
	d, err := storageConnection(spec)
	if err != nil {
		return nil, err
	}
	return openPgKind(pgOptions{dsn: d, connections: spec.connections, operation: spec.operation})
}

// storageStartLine is the start's line for the kind: which kind keeps the
// store and the registry, and the reference its connection string was read
// by -- never the string, nor any part of it.
func storageStartLine(spec *storageSpec) string {
	if spec.file != "" {
		return fmt.Sprintf("storage: the PostgreSQL storage kind keeps the store and the registry; its connection string was read from the file %s", spec.file)
	}
	return fmt.Sprintf("storage: the PostgreSQL storage kind keeps the store and the registry; its connection string was read from the environment variable %s, removed from this process's environment", spec.environment)
}
