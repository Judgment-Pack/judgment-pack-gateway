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
# The platform users: a configuration names one per platform, and the
# engine refuses a platform whose user is root, the signer's, or another
# platform's. Eight is a convention, not a limit an operator cannot raise
# with a derived image; the signer runs as engine (uid 65532, the base's
# nonroot user, renamed). Each user's home is its own alone: the mode is
# given to the COPY outright, since a directory COPY otherwise lands at
# the builder's default and not at what the build stage set.
RUN set -e; mkdir -p /out/etc /out/home; \
    printf 'root:x:0:0:root:/root:/sbin/nologin\nengine:x:65532:65532:engine signer:/home/engine:/sbin/nologin\n' > /out/etc/passwd; \
    printf 'root:x:0:\nengine:x:65532:\n' > /out/etc/group; \
    mkdir -m 0700 /out/home/engine && chown 65532:65532 /out/home/engine; \
    for n in 1 2 3 4 5 6 7 8; do \
      printf 'engine-%s:x:6560%s:6560%s:platform user %s:/home/engine-%s:/sbin/nologin\n' "$n" "$n" "$n" "$n" "$n" >> /out/etc/passwd; \
      printf 'engine-%s:x:6560%s:\n' "$n" "$n" >> /out/etc/group; \
      mkdir -m 0700 "/out/home/engine-$n" && chown "6560$n:6560$n" "/out/home/engine-$n"; \
    done

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/etc/passwd /out/etc/group /etc/
# The gateway binary is executable by the signer alone: with file
# capabilities on it, a platform user's process that executed it would
# take them up, and the engine refuses to start otherwise. The adapters
# are run by the platform users, and carry nothing.
COPY --from=build --chown=65532:65532 /out/gateway /usr/local/bin/gateway
COPY --from=build /out/adapter-airbyte /out/adapter-mcp /usr/local/bin/
COPY --from=build --chown=65532:65532 --chmod=0700 /out/home/engine /home/engine
COPY --from=build --chown=65601:65601 --chmod=0700 /out/home/engine-1 /home/engine-1
COPY --from=build --chown=65602:65602 --chmod=0700 /out/home/engine-2 /home/engine-2
COPY --from=build --chown=65603:65603 --chmod=0700 /out/home/engine-3 /home/engine-3
COPY --from=build --chown=65604:65604 --chmod=0700 /out/home/engine-4 /home/engine-4
COPY --from=build --chown=65605:65605 --chmod=0700 /out/home/engine-5 /home/engine-5
COPY --from=build --chown=65606:65606 --chmod=0700 /out/home/engine-6 /home/engine-6
COPY --from=build --chown=65607:65607 --chmod=0700 /out/home/engine-7 /home/engine-7
COPY --from=build --chown=65608:65608 --chmod=0700 /out/home/engine-8 /home/engine-8
COPY catalog/ /usr/share/engine/catalog/
COPY corpus/ /usr/share/engine/corpus/
USER engine
WORKDIR /home/engine
ENTRYPOINT ["/usr/local/bin/gateway"]
CMD ["serve", "--config", "/etc/engine/engine.json"]
