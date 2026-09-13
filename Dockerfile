# The engine image (docs/design/engine-image.md): the core binary and the
# adapter binaries built from this commit, the catalog and the frozen
# corpus, and a set of platform users -- and nothing that varies per
# deployment: no seed, no store, no registry, no configuration, no
# credential. Those live on a volume the operator mounts.
#
# Every base is pinned by the digest of its manifest index, as the catalog
# pins what it names. Both modules build with CGO disabled, so the binaries
# are static and the base needs no libc.

FROM docker.io/library/golang:1.26-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 AS build
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOWORK=off
WORKDIR /src
COPY go/ go/
COPY adapters/ adapters/
RUN cd go && go build -buildvcs=false -o /out/gateway . \
 && cd ../adapters && go build -buildvcs=false -o /out/adapter-airbyte ./cmd/adapter-airbyte \
 && go build -buildvcs=false -o /out/adapter-mcp ./cmd/adapter-mcp
# The signer runs as a user of its own and switches each adapter to its
# platform's user: that takes CAP_SETUID, CAP_SETGID and CAP_KILL, held
# as file capabilities on the gateway binary and nothing more -- no
# capability that reads past permissions, none ambient or inheritable
# (docs/design/engine-config.md, SECURITY.md). Written as the kernel's
# own attribute by build/setcap.go, so the builder needs no package for it.
COPY build/setcap.go /src/setcap.go
RUN cd /src && go run setcap.go /out/gateway && chmod 0700 /out/gateway
COPY build/mkhomes.go /src/mkhomes.go
RUN cd /src && go build -o /out/mkhomes mkhomes.go
# The platform users: a configuration names one per platform, and the
# engine refuses a platform whose user is root, the signer's, or another
# platform's. Eight is a convention, not a limit an operator cannot raise
# with a derived image; the signer runs as engine (uid 65532, the base's
# nonroot user, renamed). The homes are made in the final stage, by
# build/mkhomes.go, each its user's alone: a directory COPY lands at the
# builder's default mode whatever the source had, and the builders differ
# in what --chmod reaches, so a directory made in place is what holds on
# every builder.
RUN set -e; mkdir -p /out/etc; \
    printf 'root:x:0:0:root:/root:/sbin/nologin\nengine:x:65532:65532:engine signer:/home/engine:/sbin/nologin\n' > /out/etc/passwd; \
    printf 'root:x:0:\nengine:x:65532:\n' > /out/etc/group; \
    for n in 1 2 3 4 5 6 7 8; do \
      printf 'engine-%s:x:6560%s:6560%s:platform user %s:/home/engine-%s:/sbin/nologin\n' "$n" "$n" "$n" "$n" "$n" >> /out/etc/passwd; \
      printf 'engine-%s:x:6560%s:\n' "$n" "$n" >> /out/etc/group; \
    done

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/etc/passwd /out/etc/group /etc/
# The gateway binary is executable by the signer alone: with file
# capabilities on it, a platform user's process that executed it would
# take them up, and the engine refuses to start otherwise. The adapters
# are run by the platform users, and carry nothing.
COPY --from=build --chown=65532:65532 /out/gateway /usr/local/bin/gateway
COPY --from=build /out/adapter-airbyte /out/adapter-mcp /usr/local/bin/
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
