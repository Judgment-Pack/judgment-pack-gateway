---
status: proposed
date: 2026-09-29
deciders: maintainer
---

# A Drive connection is of the whole of a person's Drive, and files are chosen from a search of it

## Context and problem statement

A Drive connection asked for the scope `drive.file` and opened Google's own
chooser of files. Under that scope the connection sees the files it made and the
files a person chose in Google's chooser, and no others. A desk that is to work
in a person's Drive as the person does, to list a folder, find a file, read it,
make one, change one and move one to trash, each change with the person's
consent, cannot do it under that scope: it cannot see what it is asked to work on.

One try against a live account on 2026-09-29 also found that Drive gives no ETag
with a file's metadata, and Google's reference for `files.update` names no
precondition. [ADR-0005](0005-personal-storage-controls.md) holds a change of a
Drive file to a conditional request and refuses it without one. On the account
tried, every update and every move to trash was refused.

## Decision drivers

- A person's consent to a change is asked for each change, by the host, and is
  not replaced by the consent to the connection.
- What is asked of Google is one scope, named here, and no scope is asked that
  this record does not name.
- Credentials stay in the companion's custody, outside the desk and the signer.
- A public release carries no Google registration, so an installation's owner
  must be able to set the connection up in a project of their own.
- What the controls promise of a change must be what the provider lets them keep.

## Considered options

- Keep `drive.file` and Google's chooser.
- Ask for `drive.readonly` beside `drive.file`: read the whole Drive, change
  only what the connection made.
- Ask for `drive`: read and change the whole Drive.

## Decision outcome

Chosen option: "ask for `drive`", because it is the one scope under which every
operation the desk is to offer can be done, and the person's consent to each
change is kept where it was: in the host, for each change.

Determinations:

1. **The scope.** A Drive connection asks for
   `https://www.googleapis.com/auth/drive` and for nothing else. A token that
   Google says is of another scope, narrower or wider, is refused.
2. **No chooser of Google's.** The consent asks for no chooser, and the method
   `pick` is withdrawn. Drive has `search` and `select` under the contract the
   other sources have: a search of the connected Drive gives at most twenty
   files of the kinds `adapter-drive` reads, and a selection gives a grant for
   each of at most four files, for one read within five minutes.
3. **A connection made before this record** is of the narrower scope. It is
   refused when its token is next renewed, within the hour, and the person is
   asked to connect again. Nothing is moved over on its behalf.
4. **A change of a Drive file is held to the file's version.** An update and a
   move to trash read the file's version and name immediately before the change
   and refuse where either differs from what the person reviewed. They send no
   conditional request, because Drive takes none. This replaces, for Drive, the
   consequence of ADR-0005 that a Drive change fails closed without a usable
   ETag. It is decided here and built apart from the first three
   determinations: until it is built the refusal stands.
5. **What is kept.** A change is prepared as a plan that changes nothing, and
   is committed on a person's confirmation in the host. A deletion takes the
   file's exact name, is a move to trash, and is never permanent. A host must
   not expose `files-commit` as an assistant tool or as an action of a job. An
   assistant may prepare a plan for a person to read.

### Consequences

- Good, because the desk can list, find, read, make and, once determination 4
  is built, change and trash any file of the connected Drive.
- Good, because Google's Picker API is no longer needed, in a registration or
  in a desk.
- Bad, because the custody of a connection now holds a token that reads and
  changes the whole Drive. The bounds the adapters keep, of size, of kind, of a
  grant for one file and one read, are bounds on what the adapters do. They are
  not bounds on the token. A program that runs as the same user of the
  operating system and reads the custody has the whole Drive.
- Bad, because a grant no longer says that a person chose the file in Google's
  chooser. It says that the host asked to read the file. Whether a person chose
  it is the host's to keep.
- Bad, because determination 4 is weaker than a conditional request. A change
  made by another between the reading of the version and the change is
  overwritten, or trashed with the file. Drive keeps earlier versions of a file
  it holds the bytes of, and a file in trash can be put back, within limits
  that are Drive's.
- Bad, because `drive` is a scope Google restricts. An installation whose
  owner uses it themselves, or within their own organization, or as a named
  test user, needs no verification by Google. A registration offered to the
  public under this scope does. Public releases carry none, as before.
- Bad, because a host that reads the catalog must change with it: Drive's
  entry names `source-search` where it named `browser-picker`, and a selection
  answers with `resourceId` where the chooser's answered with `fileId`.
- Revisit when Drive offers a conditional change; when a registration is to be
  offered to the public; before any change is committed without a person; or
  when a narrower scope is found to serve.

## More information

- [The Drive connection](../design/drive-connections.md) and
  [the storage controls](../design/storage-files.md).
- [Drive's scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth),
  [`files.update`](https://developers.google.com/workspace/drive/api/reference/rest/v3/files/update),
  [verification of restricted scopes](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification),
  read 2026-09-29.
- Material-decision categories: public-surface, documented-claim, security.
  The cross-vendor review is recorded on the pull request that carries this
  record.
