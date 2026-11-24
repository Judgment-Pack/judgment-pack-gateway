---
status: proposed
date: 2026-11-24
deciders: maintainer
---

# The PostgreSQL instances of one database answer one key-history version: the start lease records it, and a start of the other version is refused

> **Summary.**
>
> - **Chosen:** each row of the start lease records the version of the key history its instance
>   answers at `/publickey/history`, `"1"` or `"2"` (schema version 12, migration
>   `0012_lease_key_history.sql`). A start in the several-instances mode is refused,
>   `instance-mismatch`, beside a live instance answering the other version, either way round, by a
>   sentence that names both versions and says to stop every instance.
> - **No engine version.** The member `keyHistoryVersion` and the answers are unchanged. Only a
>   mixed start, which ADR-0055 left unrefused, is now refused.
> - **Amends** [ADR-0055](0055-a-key-history-marks-each-store-continuation.md), decision 4
>   ("Several instances on one database"), decision 10 and answer 2 of its Acceptance.

## Context

ADR-0055 added a key history of version `"2"`, answered where the engine configuration sets
`keyHistoryVersion: "2"` (engine version 42) or the history carried into the store is of version
`"2"`. On the PostgreSQL kind several instances serve one database and its one registry. ADR-0055
left the mixed state unrefused: an instance that has not opted in answers `"1"` while another answers
`"2"`. Before the store's first continued rotation both answers hold for the store, so the release
notes told operators to set the member on every instance before rotating, and named a start-lease
column as a later record (gateway #583). This is that record.

A consumer that holds a gateway to version `"2"` (`--require-version 2`, ADR-0055's amendment of
2026-11-24) is refused by the instance that answers `"1"`. Behind one router, one consumer's fetches
then pass or fail by the instance they reach.

## Decision

1. **What the lease records.** Each row of `gateway.start_lease` gains `key_history`, `text`,
   `"1"` or `"2"` (a `CHECK`), default `"1"`. The instance records the version it answers: `"2"`
   where its configuration sets `keyHistoryVersion: "2"`, or where the history carried into the
   database (`gateway.key_history`) is of version `"2"`, and otherwise `"1"`. This is ADR-0055
   decision 4's rule, read once at the start, before the lease is taken. A read of the carried
   history that fails fails the start. `gateway seal-open` on this kind records the same, from the
   configuration it is given, so it is admitted beside the instances it serves beside.
2. **The refusal.** `admitBeside` compares the version with each live row, after the key id, the
   authority and the reading of sessions. A start answering another version is refused,
   `instance-mismatch`:

   > gateway instance `<holder>` serves the database answering the key history of version "1", and
   > this instance answers version "2"; every instance serving one database at once answers one key
   > history: the move to keyHistoryVersion "2" is not made one instance at a time; stop every
   > instance, and start them all with one keyHistoryVersion (ADR-0062)

   Rows that ran out are not compared (ADR-0035, decision 8): once every instance has stopped, a
   start of either version is admitted.
3. **The migration.** Schema version 12 is one `ALTER TABLE … ADD COLUMN`. A row from before it reads
   `"1"`, the version every instance of an earlier schema answered unless it set the member, and the
   migration runs with every instance stopped, so no live row is compared under the default. The run-time
   login's grants on the table are unchanged. A v0.40.0 gateway already refuses schema 11, and refuses
   12 for the same reason.
4. **The one-instance mode** is unchanged: it is refused beside any live row first.

## Consequences

- **Good:** one database's instances answer one version, so a consumer's check does not depend on the
  instance a router reaches.
- **Good:** no change to an answer, a receipt, the member or the engine version.
- **Bad:** moving the instances of one database to `keyHistoryVersion: "2"` is a stop-all change, as
  the move to session labels is (ADR-0051). A rolling change of the member is refused at the first
  instance that would differ.
- **Bad:** one more read at the start, of the carried history's single row.

## What is not established

- A store rotation that carries a version `"2"` history into a database whose instances are still
  serving: the rotation runs with every instance stopped, so none is compared.
