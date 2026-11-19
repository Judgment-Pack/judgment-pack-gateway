---
status: accepted (autopilot; maintainer may revise)
date: 2026-11-19
deciders: maintainer
---

# A scoped platform's live tools are declared read-external, whatever the front

## Context and problem statement

ADR-0044 holds an MCP front that names `mcp.scope` or `mcp.scopeFrom: "caller"` to live tools
declared effect `read-external`, and refuses both starts otherwise. It is the front's rule. In
a configuration with no `mcp` member, a caller that reaches a platform fixed to a scope
identifier (ADR-0037) can still send `/acquire` naming that platform's live tool declared
`act` or `propose`, and the signer runs it. The call is receipted, but no decision policy
holds it: a decision policy is a write operation's, and a platform fixed to a scope identifier
enables no write operation, since `/act` takes no scope (ADR-0026, decision 4). So the one
write path such a platform has is the one no decision holds, and whether it is open depends
on whether the file names an MCP front. ADR-0044 left this open ("not decided here"). Issue
#519.

## Decision drivers

- A platform fixed to a scope identifier writes nothing that a decision does not hold, by any
  route: ADR-0026 already refuses `write: true` beside `scope` for this reason.
- The property is read from the configuration, not from which processes the operator runs.
- A misdeclared tool is found at start, by name, not at a call by a caller.
- One rule in one function, applied by every start that reads the configuration.
- A platform of no scope identifier is unchanged where ADR-0044 left it unchanged.

## Considered options

- (a) Every start refuses a platform fixed to a scope identifier whose live tools are not all
  declared `read-external`, whatever the front.
- (b) Keep direct acquisition of such a tool allowed: the credential the operator gives the
  tool keeps it to reading, and the signer's caller is the operator's own program. Not taken:
  the declaration says the tool acts, and no decision holds the act. A caller of one scope
  identifier would reach, through its own platform, an act that no caller of that platform
  can reach through the front, so the rule would hang on a member the file need not name.
- Refuse at `/acquire` only: start as before, and answer a call of such a tool with a refusal
  before its source runs. Not taken: the configuration would start with tools that can only be
  refused, the operator would learn of it from a caller (ADR-0044's reason for not listing and
  refusing), and the rule would be stated a second time at the call. It would not save a
  configuration that uses the tool: its call is refused either way.
- Gate the rule behind a new engine configuration version. Not taken: see decision 4.

The code shows no configuration this breaks that the design allows. The case it does break is
a scoped platform of a binding whose live operation names an act it calls through `/acquire`,
such as the shipped postgres binding's `execute_sql` run under a role that only reads. That is
the case ADR-0044, decision 6 already moved off a scoped front, and its ways out (decision 5)
are the same.

## Decision outcome

Chosen option: (a), because a platform fixed to a scope identifier has no write that a
decision holds, and the start is where the operator can fix a declaration.

1. **The rule.** Each live tool of each platform fixed to a scope identifier declares effect
   `read-external`, whether the configuration names no `mcp`, an `mcp` fixed to a scope
   identifier, or one that takes its callers' (`scopeFrom: "caller"`). Under `mcp.scope` that
   includes the platforms fixed to another scope identifier, which ADR-0044 did not read.
   ADR-0044's rule for the caller form's platforms of no scope identifier (its decision 3)
   stands: they are held too, behind that form alone. A tool declared `propose` or `act`, one
   the binding declares nothing for, and any other declaration refuse the start, as ADR-0044,
   decision 1 lists them.
2. **The refusal.** One sentence, for both rules:
   `platform <name>: tool "<tool>" is not declared effect read-external, and a platform fixed
   to a scope identifier, or one an MCP server that names scopeFrom serves, takes no other live
   tool, since no decision policy holds a live tool's call (ADR-0044, ADR-0046); declare the
   tool read-external if it only reads, or move it to a platform of no scope identifier, with
   no mcp or an mcp that names neither scope nor scopeFrom`. Its first clause is ADR-0044's,
   unchanged; the rest is restated for the wider rule. It names the platform and the tool and
   nothing else: no scope identifier, no other tool, nothing of the declaration.
3. **Where it is applied.** ADR-0044's one function, widened and renamed `scopedLiveReads`
   (`go/mcp_scope.go`), called where ADR-0044 calls it: `serve` (`engineStart`, on either
   storage kind), `gateway mcp` (`newMCPServer`, over `--http` and `--stdio`), and `connect`
   before any adapter is asked (so `connect --replace` of a scoped platform, which keeps its
   `scope`, refuses such a binding). It comes before the owners' general check (ADR-0021), so a
   tool with no declaration is named. Every signer starts through `engineStart`, so no
   `/acquire` of such a tool reaches its adapter. Nothing is added at `/acquire`: the rule is
   stated once. `gateway posture` still reads such a file.
4. **No engine configuration version.** No member is added and the file's form is unchanged:
   what changes is what this binary starts, as with ADR-0044, which changed both starts without
   a version. A version gate would leave the write path open in every file that does not raise
   its version, which is every file written before; a safeguard a file opts out of by keeping
   its version does not hold. A gateway older than this one starts such a file as before.
5. **A configuration that breaks.** A file of any version from 20 that fixes a platform to a
   scope identifier and whose live operation names a tool declared `propose` or `act` no
   longer starts `serve` or `gateway mcp`, with the sentence of decision 2; it is refused by
   name, never served with the tool left out. The operator does one of two things:
   - If the tool only reads, meaning its server's tool and the credential it is given read and
     nothing else: declare it `read-external` (for instance `{"operation": "read", "effect":
     "read-external"}`) in the binding's `toolTaxonomies`, and approve the binding again with
     `connect --replace`.
   - Otherwise, take it off the scoped platform: pin a binding whose live operation names
     reading tools alone, or remove the platform's `scope` and serve it as a platform of no
     scope identifier, with no `mcp`, or with an `mcp` of neither form where no platform of the
     configuration is fixed to one (ADR-0038, decision 10). Its receipts then carry no scope,
     and its callers must reach the sources of none (ADR-0037).
6. **What is unchanged.** A platform of no scope identifier serves an `act` live tool as
   before, under no `mcp`, an `mcp` of neither form, or an `mcp` fixed to a scope identifier
   (which does not serve it). A live operation of the `http` or `gcp-asset` shape names no
   tools and is not read (ADR-0024, ADR-0039), nor is a history operation. A scoped platform's
   write operation stays refused (ADR-0026). No request, response, receipt, vector, verifier or
   schema changes; SPEC.md's statement that a scoped platform allows no write is unchanged and
   now holds of its live tools by declaration too.
7. **ADR-0044 narrowed.** Its decision 5 sentence "A configuration with no `mcp` member is not
   read by this rule", its decision 5 sentence on a front fixed to a scope identifier not
   holding another identifier's platforms, and its consequence "not decided here" are
   superseded by decisions 1 and 3. Its decisions 1 to 4 and 6 stand, widened as above.

### Consequences

- Good, because a platform fixed to a scope identifier acts on nothing that no decision holds,
  by the front or by the signer, and that is read from the platform's `scope` alone.
- Good, because the rule is still one function at every start, and its refusal one sentence.
- Bad, because the change is breaking without a version: a scoped configuration with an act or
  propose live tool and no scoped front, which started before, stops at start until the
  operator redeclares and re-approves the tool or moves it.
- Bad, because, as under ADR-0044, the rule holds a declaration, not a behaviour: a tool
  declared `read-external` that writes is run, and what keeps it to reading is the credential.
- Bad, because a scoped platform of the shipped postgres binding starts only once its operator
  declares `execute_sql` `read-external` in a binding of its own, under a role that only reads,
  or pins a binding of `search_objects` alone.
- Revisit when a decision policy can hold a live tool's call or `/act` takes a scope.

## More information

- Issue #519; ADR-0044 (decisions 1, 5 and 6, and its last consequence); ADR-0026 (decision 4);
  ADR-0037; ADR-0038 (decisions 3 and 10); ADR-0021.
- `go/mcp_scope.go` (`scopedLiveReads`), `go/main.go` (`engineStart`), `go/mcp.go`
  (`newMCPServer`), `go/connect.go`; tests in `go/mcp_scoped_reads_test.go` and
  `go/mcp_caller_scope_e2e_test.go`.
- SECURITY.md ("What holds between scope identifiers on one gateway"); `docs/design/engine-config.md`
  ("A platform's scope (engine version 20)", "The MCP server on scoped platforms (engine version
  28)"); `docs/design/mcp-server.md` ("Scope identifiers", "Writes").
