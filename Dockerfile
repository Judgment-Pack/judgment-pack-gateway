# The engine image (docs/design/engine-image.md): the core binary and the
# adapter binaries built from this commit, the catalog and the frozen
# corpus, the source sandbox's launcher, and a set of platform users -- and
# nothing that varies per deployment: no seed, no store, no registry, no
# configuration, no credential. Those live on a volume the operator mounts.
#
# Every base is pinned by the digest of its manifest index, as the catalog
# pins what it names, and the bubblewrap source and the Go modules are
# fetched by their content. The launcher stage's compiler, build tools and
# the two libraries it links are not: they are installed from the pinned
# Alpine release's signed package repository as it stands when the image
# is built, held only to the upstream versions the launcher's notices name
# (below). Both modules build with CGO disabled, so the binaries are static and the base needs no
# libc. The runtime is not built here: it is the released binary, taken
# from the runtime's own distribution image at the pinned digest, so the
# bytes are the ones that release attests.
#
# One Dockerfile for every platform the release publishes (linux/amd64 and
# linux/arm64, build/engine-image.sh): the modules are compiled on the
# builder's own platform for the target's, and only the stages that must
# run on the target -- the launcher's compiler and the homes -- do.

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 AS build
ARG TARGETOS
ARG TARGETARCH
# The release tag, written into the gateway as the release archives write
# it (.goreleaser.yml); empty outside a release, which leaves the binary
# reporting what an unstamped build reports.
ARG RELEASE_VERSION
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOWORK=off
WORKDIR /src
COPY go/ go/
COPY adapters/ adapters/
RUN export GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
 && cd go && go build -buildvcs=false ${RELEASE_VERSION:+"-ldflags=-X=main.releaseVersion=${RELEASE_VERSION}"} -o /out/gateway . && cp /out/gateway /out/engine-mcp \
 && cd ../adapters && go build -buildvcs=false -o /out/adapter-airbyte ./cmd/adapter-airbyte \
 && go build -buildvcs=false -o /out/adapter-mcp ./cmd/adapter-mcp \
 && go build -buildvcs=false -o /out/adapter-sandbox ./cmd/adapter-sandbox \
 && go build -buildvcs=false -o /out/adapter-http ./cmd/adapter-http \
 && go build -buildvcs=false -o /out/adapter-document ./cmd/adapter-document
# The signer runs as a user of its own and switches each adapter to its
# platform's user: that takes CAP_SETUID, CAP_SETGID and CAP_KILL, held
# as file capabilities on the gateway binary and nothing more -- no
# capability that reads past permissions, none ambient or inheritable
# (docs/design/engine-config.md, SECURITY.md). Written as the kernel's
# own attribute by build/setcap.go, so the builder needs no package for it.
COPY build/setcap.go /src/setcap.go
RUN cd /src && go run setcap.go /out/gateway && chmod 0700 /out/gateway
COPY build/mkhomes.go /src/mkhomes.go
RUN cd /src && GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -o /out/mkhomes mkhomes.go
# The platform users: a configuration names one per platform, and the
# engine refuses a platform whose user is root, the signer's, the MCP
# server's, or another platform's. Eight is a convention, not a limit an operator cannot raise
# with a derived image; the signer runs as engine (uid 65532, the base's
# nonroot user, renamed). The homes are made in the final stage, by
# build/mkhomes.go, each its user's alone: a directory COPY lands at the
# builder's default mode whatever the source had, and the builders differ
# in what --chmod reaches, so a directory made in place is what holds on
# every builder.
RUN set -e; mkdir -p /out/etc; \
    printf 'root:x:0:0:root:/root:/sbin/nologin\nengine:x:65532:65532:engine signer:/home/engine:/sbin/nologin\nengine-mcp:x:65533:65533:engine MCP server:/home/engine-mcp:/sbin/nologin\n' > /out/etc/passwd; \
    printf 'root:x:0:\nengine:x:65532:\nengine-mcp:x:65533:\n' > /out/etc/group; \
    for n in 1 2 3 4 5 6 7 8; do \
      printf 'engine-%s:x:6560%s:6560%s:platform user %s:/home/engine-%s:/sbin/nologin\n' "$n" "$n" "$n" "$n" "$n" >> /out/etc/passwd; \
      printf 'engine-%s:x:6560%s:\n' "$n" "$n" >> /out/etc/group; \
    done

# The source sandbox's launcher (docs/adr/0030-the-engine-image-carries-the-sandbox-launcher.md):
# bubblewrap, built from its released source, pinned by content, as one
# static executable linked with musl and libcap -- no program interpreter,
# no library search path, nothing the launcher's own check
# (adapters/internal/sandbox, trustedFile) would have to follow -- and
# /bin/true, which bubblewrap's start check runs inside the sandbox. The
# source is pinned by content; the compiler and the two libraries are not.
# They are the pinned Alpine release's, as its signed repository has them
# when the image is built, at whatever package revision it then serves:
# the step below refuses a build that would link other upstream versions
# than the notices beside the launcher name, so the notices cannot drift
# from what is linked, but a new revision of the same version is taken. The
# source travels with the binary, as its licence asks; the two libraries'
# licences are in build/notices, copied from their upstream repositories at
# those versions (musl's COPYRIGHT at v1.2.6, libcap's License at
# libcap-2.78), so that a build fetches nothing but the source.
FROM docker.io/library/alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS launcher
RUN apk add --no-cache build-base meson libcap-dev libcap-static linux-headers pkgconf
ADD --checksum=sha256:0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d https://github.com/containers/bubblewrap/releases/download/v0.13.1/bubblewrap-0.13.1.tar.xz /out/notices/bubblewrap-source.tar.xz
COPY build/notices/musl-COPYRIGHT build/notices/libcap-License /out/notices/
RUN set -e; \
    linked="$(apk list --installed musl libcap-static | cut -d ' ' -f 1 | sort | tr '\n' ' ')"; \
    case "$linked" in \
      "libcap-static-2.78-r"*" musl-1.2.6-r"*) ;; \
      *) echo "the notices name libcap 2.78 and musl 1.2.6; this builder would link: $linked" >&2; exit 1 ;; \
    esac; \
    mkdir -p /build && tar -xJf /out/notices/bubblewrap-source.tar.xz -C /build; \
    cd /build/bubblewrap-0.13.1; \
    meson setup _build --buildtype=release -Dselinux=disabled -Dman=disabled -Dtests=false \
      -Dbash_completion=disabled -Dzsh_completion=disabled --prefer-static -Dc_link_args=-static; \
    meson compile -C _build bwrap; \
    install -m 0755 -s _build/bwrap /out/bwrap; \
    printf 'int main(void) { return 0; }\n' > /build/true.c; \
    gcc -static -Os -s -o /out/true /build/true.c; \
    for program in /out/bwrap /out/true; do \
      if readelf -l "$program" | grep -q INTERP; then echo "$program names a program interpreter" >&2; exit 1; fi; \
    done; \
    cp COPYING /out/notices/bubblewrap-COPYING; \
    printf '%s\n' \
      '/usr/bin/bwrap is bubblewrap 0.13.1, built from bubblewrap-source.tar.xz (its release 0.13.1) beside this file, unchanged,' \
      'and linked statically with the musl C library and libcap. /bin/true is a program of one line' \
      'linked statically with musl. Their licences: bubblewrap-COPYING (bubblewrap, LGPL-2.0-or-later),' \
      'musl-COPYRIGHT (musl, MIT), libcap-License (libcap, BSD-3-Clause or GPL-2.0-only).' \
      "Linked here: $linked" > /out/notices/README; \
    chmod 0644 /out/notices/*

# The runtime pin: one line, the tag for the reader and the digest for the
# builder. The runtime image is the released static binary on scratch, with
# its notices beside it; nothing else of it is taken.
FROM ghcr.io/judgment-pack/judgment-pack:0.46.0@sha256:5202a1f0ce009952ff9bf487e64ea89e662288cf8f6a2c9f0cd935f5c18a9778 AS runtime

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/etc/passwd /out/etc/group /etc/
# The adapters first, so that the directories on the way -- which the
# base does not carry -- are made by this COPY as root's: a COPY that
# chowns makes the directories it has to make for its owner, and a
# /usr/local/bin the signer owned would be a /usr/local/bin the signer
# could put another adapter in for a platform user to run. The adapters
# are run by the platform users, and carry nothing. Then the gateway,
# executable by the signer alone: with file capabilities on it, a
# platform user's process that executed it would take them up, and the
# engine refuses to start otherwise.
COPY --from=build /out/adapter-airbyte /out/adapter-mcp /out/adapter-http /out/adapter-document /out/adapter-sandbox /usr/local/bin/
# The runtime beside them, root's and executable by everyone like the
# adapters: it holds no seed and no credential, and whoever runs it -- a
# desk, an orchestrator, a shell in a derived image -- runs it as itself.
# Its notices travel with it, and its conformance statement, which every
# evaluation payload it writes points the reader at.
COPY --from=runtime /jpack /usr/local/bin/jpack
COPY --from=runtime /LICENSE /NOTICE /THIRD_PARTY_NOTICES /CONFORMANCE.md /usr/share/engine/runtime/
COPY --from=build --chown=65532:65532 /out/gateway /usr/local/bin/gateway
# The MCP server (docs/design/mcp-server.md): the same executable, copied
# before the capabilities were written to the signer's, root's and
# executable by everyone with no attribute -- run as engine-mcp, a user
# of its own that no group of the signer's or a platform's admits, under
# its `mcp` subcommand. The signer's 0700 binary is never the one that
# process runs.
COPY --from=build /out/engine-mcp /usr/local/bin/engine-mcp
# The source sandbox's launcher at the first of the fixed locations the
# launcher looks in, and the program its start check runs: root's,
# executable by everyone, no set-user-id bit and no capability -- it
# needs user namespaces as the source's user, which the container's
# runtime gives or refuses (docs/design/engine-image.md, "The source
# sandbox"). Their notices beside the engine's own, and the gateway's
# licence and the notices of what its programs link, since the image is
# published as the archives are.
COPY --from=launcher /out/bwrap /usr/bin/bwrap
COPY --from=launcher /out/true /bin/true
COPY --from=launcher /out/notices/ /usr/share/engine/bubblewrap/
COPY LICENSE THIRD_PARTY_NOTICES /usr/share/engine/
# The homes, made in place as root -- the base's own user is nonroot, so
# root is taken for this one step and given back below -- and each given
# to its user; the helper removes itself, so the final filesystem carries
# it as a whiteout only.
COPY --from=build /out/mkhomes /mkhomes
USER 0
RUN ["/mkhomes"]
COPY catalog/ /usr/share/engine/catalog/
COPY corpus/ /usr/share/engine/corpus/
USER engine
WORKDIR /home/engine
ENTRYPOINT ["/usr/local/bin/gateway"]
CMD ["serve", "--config", "/etc/engine/engine.json"]
