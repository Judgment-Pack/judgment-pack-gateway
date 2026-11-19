---
status: proposed
date: 2026-11-18
deciders: maintainer
---

# A scoped MCP front serves only live tools declared read-external

## Context and problem statement

The MCP front builds its tool table from every tool of each served platform's `live` operation.
A tool's declared effect only sets its annotations: an `act` tool is listed with
`destructiveHint: true` and served (ADR-0021; `docs/design/mcp-server.md`, "Writes"). On a front
of neither form this is the operator's choice. On a front that names `mcp.scope` or
`mcp.scopeFrom: "caller"` (ADR-0038) it puts an acting tool in front of every caller of a scope
identifier, and nothing holds the call. The call is receipted, but no decision policy holds a
live tool: a decision policy is a write operation's, and a platform fixed to a scope identifier
can enable no write operation, since `/act` takes no scope (ADR-0026, decision 4). Issue #516.

## Decision drivers

- A front shared by the callers of several scope identifiers carries no write that a decision
  does not hold.
- A misdeclared tool is found at start, not missing at a call: nothing is left out silently.
- A refusal names what the operator must change, and nothing of a scope identifier.
- One rule, applied by every start that reads the configuration.
- A front of neither form, and every configuration without a scoped front, is unchanged.

## Considered options

- Keep today's behaviour: the effect sets the annotations, and the credential keeps a tool to
  reading. Not taken: on a scoped platform the live tool would be the one write path, and the
  one no decision holds.
- Leave a tool that is not a read out of the table. Not taken: a misdeclared read would be found
  missing at a call, with nothing saying why.
- List the tool and refuse its call. Not taken: the front would list what it does not serve, and
  the operator would learn of it from a caller.
- Hold only the platforms fixed to a scope identifier, so the caller form still serves the act
  tools of its platforms of none. Not taken: see decision 3.
- Bring a decision policy to a scoped platform's live tools. Not taken here: `/act` takes no
  scope, and a policy is the write operation's; that is a larger change.

## Decision outcome

Chosen option: a front of either form refuses to start where a live tool it would serve is not
declared effect `read-external`, because a front no decision can hold must not act, and a
refusal at start is where the operator can fix it.

1. **The rule.** Where `mcp` names `scope` or `scopeFrom`, each live tool of each platform the
   front serves declares effect `read-external` (`go/taxonomy.go`; the operations `discover`,
   `read`, `answer`, `check` and `run` can carry it). Under `mcp.scope` that is every platform
   fixed to its scope identifier. Under `scopeFrom: "caller"` it is every platform, those of no
   scope identifier included (decision 3). A tool declared `propose` or `act`, a tool the
   binding declares nothing for, and any other declaration refuse the start. The effect `read`,
   the engine's own state, is already refused for a tool when the binding is read.
2. **The refusal.** One sentence: `platform <name>: tool "<tool>" is not declared effect
   read-external`, then the rule and the two ways out (decision 6). It names the platform and
   the tool and nothing else: no scope identifier, no other tool, nothing of the declaration.
   It comes before the general check of the owners (ADR-0021), so a tool with no declaration is
   named rather than its binding refused as a whole.
3. **The caller form's platforms of no scope identifier are held too.** ADR-0038 (decision 3)
   lets the caller form serve every platform, those of none among them, to the callers whose
   token reaches the sources of none. That stands, held to reads. The caller form is one
   process, one listing and one admission path shared by the callers of every scope identifier.
   Holding all of it to reads makes "this front acts on nothing" a property of the form, which
   an operator and a reviewer read from the configuration, not from each platform's binding.
   A mistake in `identity.callerScopes`, such as a scoped party's subject granted `"unscoped"`
   or `"installation"`, then exposes reads at most, never an act.
4. **Where it is applied.** One function (`go/mcp_scope.go`, `scopedFrontReads`), called by
   both starts: `gateway mcp` as it builds its table (`newMCPServer`, over `--http` and
   `--stdio`), and `serve` (`engineStart`), on either storage kind. `serve` does not run the
   front, but the file is one. A configuration the front would refuse does not start the
   signer either, as with the owners' general check. `connect` holds the configuration it would
   write to the same rule before any adapter is asked, as it holds it to every refusal `serve`
   applies. The rule is not in the file's parse: the declarations are the bindings', read after
   the file. `gateway posture` still reads such a file.
5. **What is unchanged.** A front of neither form serves an `act` live tool as before. A
   configuration with no `mcp` member is not read by this rule. A binding's write operation has
   no MCP tool in either form (ADR-0038, decision 8). The seal tool is the engine's own and is
   not a live tool. A front fixed to one scope identifier serves no platform of another, so
   those platforms are not held by this rule. No receipt, vector or verifier changes.
6. **An existing configuration.** A file that started before, names `scope` or `scopeFrom`, and
   serves a live tool not declared `read-external`, now fails both starts with the sentence of
   decision 2. The operator does one of two things:
   - If the tool only reads, meaning its server's tool and the credential it is given read and
     nothing else: declare it `read-external` (for instance `{"operation": "read", "effect":
     "read-external"}`) in the binding's `toolTaxonomies`, and approve the binding again with
     `connect --replace`. The declaration is part of the pinned binding and of the approved
     snapshot.
   - Otherwise, take it off the scoped front. Pin a binding whose live operation names reading
     tools alone, or serve the platform with no scope identifier behind an `mcp` of neither
     form. That needs a configuration with no platform fixed to a scope identifier (ADR-0038,
     decision 10).

   A shipped binding whose live operation names an act (the postgres binding's `execute_sql`)
   is therefore not served by a scoped front at all.

### Consequences

- Good, because every tool a scoped front lists is declared a read of a system outside the
  engine, so no caller reaches an act through it that no decision holds.
- Good, because a misdeclared tool stops the start with its name, rather than being served or
  missing.
- Good, because one function holds both starts and `connect`.
- Bad, because the change is breaking: a scoped configuration with such a tool no longer starts
  until the operator redeclares and re-approves the tool, or moves it.
- Bad, because the rule holds a declaration, not a behaviour. A tool declared `read-external`
  that writes is served, and what keeps it to reading is still the credential the operator
  gives it (`docs/design/mcp-server.md`, "Writes"). The declaration is the operator's word,
  reviewed when the binding is approved.
- Bad, because an installation with any platform fixed to a scope identifier serves no act live
  tool over MCP, its caller form's platforms of none included. An operator who needs one runs a
  configuration with no scoped platform for it.
- Bad, because this is the front's rule. A caller that sends `/acquire` to the signer itself
  can still name a scoped platform's act live tool. Beside `mcp` the signer listens on loopback
  alone, but a configuration without `mcp` may listen off loopback. Holding the signer's live
  sources of a scoped platform to reads is not decided here; #519 tracks it.
- Revisit when a decision policy can hold a live tool's call, when `/act` takes a scope, or when
  the signer's own live sources of a scoped platform are held to reads.

## More information

- Issue #516; ADR-0021, ADR-0026 (decision 4), ADR-0038 (decisions 2, 3 and 8).
- `go/mcp_scope.go` (`scopedFrontReads`), `go/mcp.go` (`newMCPServer`), `go/main.go`
  (`engineStart`), `go/connect.go`; tests in `go/mcp_scoped_reads_test.go`.
- SPEC.md §6 ("The MCP server on scoped platforms"); `docs/design/mcp-server.md` ("Scope
  identifiers", "Writes"); `docs/design/engine-config.md` ("The MCP server on scoped platforms
  (engine version 28)"); `docs/design/tool-descriptors.md` ("What a served tool carries of its
  owner").
