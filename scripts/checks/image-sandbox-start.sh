#!/usr/bin/env bash
# CI step: With measureSandboxAtStart on, the engine starts only where its posture says each source would launch
# measureSandboxAtStart (engineVersion 23; docs/design/engine-config.md,
# "Measuring the sandbox at the start"), in the engine image as built, with
# one synthetic platform whose source is never launched:
#
# - Where no source sandbox can be had, the engine with the member on names
#   the source, does not start, and makes no store; the same engine without
#   the member (version 22) starts, as it always did, and its posture says
#   the sandbox is not enforced -- each launch is what refuses there. The
#   host is made one without a sandbox by seccomp: a profile that refuses
#   user namespaces, which bubblewrap takes, and Landlock, and allows the
#   rest; where the host's seccomp library cannot name Landlock's calls,
#   that profile leaves them allowed, and Docker's default profile, which
#   admits only the calls it names, is used instead. A host on which
#   neither leaves the engine without a sandbox fails this step: the
#   refusal is not left unexercised.
# - Under seccomp=unconfined, whatever the host gives, the start with the
#   member on agrees with gateway posture: it starts and states the
#   measurement posture reports, or refuses where posture says not enforced.
# - The launcher the image carries enforces: under seccomp=unconfined, with
#   the host's mandatory access control profile relaxed as well where
#   `docker info` lists one (apparmor=unconfined for AppArmor,
#   label=disable for SELinux), since such a profile may refuse the
#   mounts bubblewrap makes in its namespace, posture says workspace-write bubblewrap enforced and the start with the
#   member on says the same. Anything else -- Landlock, partial, none -- is
#   a fallback and fails this step. What seccomp=unconfined alone gives is
#   printed beside it where a profile was relaxed.
set -e
dir="$(mktemp -d)"
containers=()
cleanup() {
  for c in "${containers[@]}"; do docker rm -f "${c}" >/dev/null 2>&1 || true; done
  sudo chown -R "$(id -u):$(id -g)" "${dir}"
  rm -rf "${dir}"
}
trap cleanup EXIT
mkdir -p "${dir}/etc" "${dir}/catalog" "${dir}/secrets" "${dir}/state"
printf '%s' '{"bindingVersion":"1","platform":"records","operations":{"live":{"shape":"http","endpoint":"https://records.example/api","paths":["/health"],"methods":["GET"],"bearer":"API_TOKEN","checkPath":"/health","licence":"MIT"}}}' > "${dir}/catalog/records.json"
binding="records@sha256:$(sha256sum "${dir}/catalog/records.json" | cut -d ' ' -f 1)"
printf '%s' '{"API_TOKEN":"synthetic-token"}' > "${dir}/secrets/records.json"
chmod 0600 "${dir}/secrets/records.json"
chmod 0700 "${dir}/state"
config() {
  printf '{"engineVersion":"%s","authority":"gateway:ci","seed":"/var/lib/engine/gateway.seed","store":"/var/lib/engine/store","registry":"/var/lib/engine/registry.jsonl","decisionRecords":"/var/lib/engine/decisions","listen":"127.0.0.1:8787","catalog":"/srv/catalog","adapters":"/usr/local/bin"%s,"platforms":{"records":{"binding":"%s","credentials":{"live":{"file":"/run/secrets/records.json"}},"user":"engine-1"}}}' "$1" "$2" "${binding}" > "${dir}/etc/$3"
}
config 23 ',"measureSandboxAtStart":true' measured.json
config 22 '' unmeasured.json
# unshare and setns refused, clone refused a new user namespace, clone3
# answered as absent so that a caller falls back to clone, and Landlock's
# three calls refused; everything else allowed.
cat > "${dir}/no-sandbox.json" <<'EOF'
{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[
{"names":["unshare","setns","landlock_create_ruleset","landlock_add_rule","landlock_restrict_self"],"action":"SCMP_ACT_ERRNO","errnoRet":1},
{"names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":268435456,"valueTwo":268435456,"op":"SCMP_CMP_MASKED_EQ"}]},
{"names":["clone3"],"action":"SCMP_ACT_ERRNO","errnoRet":38}
]}
EOF
# The owners the engine holds each file to: the catalog and the
# credentials' directory root's, the credential the platform user's alone,
# the state directory the signer's.
sudo chown -R 0:0 "${dir}/etc" "${dir}/catalog" "${dir}/secrets"
sudo chown 65601:65601 "${dir}/secrets/records.json"
sudo chown 65532:65532 "${dir}/state"
mounts=(-v "${dir}/state:/var/lib/engine" -v "${dir}/etc:/etc/engine:ro" -v "${dir}/catalog:/srv/catalog:ro" -v "${dir}/secrets:/run/secrets:ro")
docker run --rm "${mounts[@]}" engine:ci keygen /var/lib/engine/gateway.seed >/dev/null

# --security-opt for each setting given; an empty one is Docker's default.
security_opts() {
  opts=()
  local o
  for o in "$@"; do [ -z "${o}" ] || opts+=(--security-opt "${o}"); done
}
# The source's entry in gateway posture under the security settings given
# (none, or an empty one: Docker's default): its mode, backend and state.
measured() {
  local opts
  security_opts "$@"
  docker run --rm "${opts[@]}" "${mounts[@]}" engine:ci posture --config /etc/engine/measured.json |
    awk '$1 == "records/live" && $2 == "adapter" { print $3, $4, $5; exit }'
}
# serve --config <file> under the security settings given after it, in a
# container of its own: 0 once it serves, 1 once it has exited; its logs
# are in ${log}.
serve() {
  local opts c config=$1
  shift
  security_opts "$@"
  c="$(docker run -d "${opts[@]}" "${mounts[@]}" engine:ci serve --config "/etc/engine/${config}")"
  containers+=("${c}")
  for _ in $(seq 1 90); do
    log="$(docker logs "${c}" 2>&1)"
    if printf '%s\n' "${log}" | grep -q '^gateway on http://'; then
      docker rm -f "${c}" >/dev/null
      return 0
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "${c}")" != true ]; then
      log="$(docker logs "${c}" 2>&1)"
      exited="$(docker inspect -f '{{.State.ExitCode}}' "${c}")"
      return 1
    fi
    sleep 1
  done
  echo "serve --config ${config} neither served nor exited: ${log}"
  exit 1
}

setting="" found=""
for candidate in "seccomp=${dir}/no-sandbox.json" ""; do
  if [ "$(measured "${candidate}")" = "workspace-write none not-enforced" ]; then
    setting="${candidate}" found=1
    break
  fi
done
[ -n "${found}" ] || {
  echo "neither seccomp setting leaves this host without a source sandbox (the profile: $(measured "seccomp=${dir}/no-sandbox.json"); Docker's default: $(measured ""))"
  exit 1
}

if serve measured.json "${setting}"; then echo "the engine started with measureSandboxAtStart on and no sandbox to be had: ${log}"; exit 1; fi
[ "${exited}" = 1 ] || { echo "the refused start exited ${exited}: ${log}"; exit 1; }
printf '%s\n' "${log}" | grep -q '^start: measureSandboxAtStart: source records/live: workspace-write is not enforced under none: .*; the engine does not start' || { echo "the start was refused for another reason: ${log}"; exit 1; }
if sudo test -e "${dir}/state/store"; then echo "the refused start made the store"; exit 1; fi

serve unmeasured.json "${setting}" || { echo "without the member the engine did not start: ${log}"; exit 1; }
if printf '%s\n' "${log}" | grep -q measureSandboxAtStart; then echo "without the member the start measured the sandbox: ${log}"; exit 1; fi

posture="$(measured seccomp=unconfined)"
[ -n "${posture}" ] || { echo "gateway posture names no entry for records/live"; exit 1; }
if [ "${posture##* }" = not-enforced ]; then
  if serve measured.json seccomp=unconfined; then echo "posture says ${posture}, and the start with the member on served: ${log}"; exit 1; fi
  printf '%s\n' "${log}" | grep -q '^start: measureSandboxAtStart: source records/live: ' || { echo "posture says ${posture}, and the start was refused for another reason: ${log}"; exit 1; }
else
  serve measured.json seccomp=unconfined || { echo "posture says ${posture}, and the start with the member on was refused: ${log}"; exit 1; }
  printf '%s\n' "${log}" | grep -qx "start: measureSandboxAtStart: measured records/live ${posture}" || { echo "posture says ${posture}, and the start says otherwise: ${log}"; exit 1; }
fi

relaxed=(seccomp=unconfined)
security="$(docker info --format '{{json .SecurityOptions}}')"
case "${security}" in *name=apparmor*) relaxed+=(apparmor=unconfined) ;; esac
case "${security}" in *name=selinux*) relaxed+=(label=disable) ;; esac
want="workspace-write bubblewrap enforced"
enforcing="$(measured "${relaxed[@]}")"
host() {
  echo "  docker security options: ${security}"
  local f
  for f in /proc/sys/kernel/apparmor_restrict_unprivileged_userns /proc/sys/kernel/unprivileged_userns_clone /proc/sys/user/max_user_namespaces; do
    [ ! -r "${f}" ] || echo "  ${f}: $(cat "${f}")"
  done
}
if [ "${enforcing}" != "${want}" ]; then
  echo "under ${relaxed[*]} posture says ${enforcing:-nothing} for records/live, not ${want}: the launcher falls back on this host"
  host
  exit 1
fi
if serve measured.json "${relaxed[@]}"; then :; else
  echo "under ${relaxed[*]} posture says ${want}, and the start with the member on was refused: ${log}"
  host
  exit 1
fi
printf '%s\n' "${log}" | grep -qx "start: measureSandboxAtStart: measured records/live ${want}" || { echo "under ${relaxed[*]} posture says ${want}, and the start says otherwise: ${log}"; exit 1; }
alone=""
[ "${#relaxed[@]}" = 1 ] || alone="; seccomp=unconfined alone: $(measured seccomp=unconfined)"
echo "with measureSandboxAtStart on the engine starts only where its posture says the source would launch (unconfined here: ${posture}); the launcher enforces under ${relaxed[*]}${alone}"
