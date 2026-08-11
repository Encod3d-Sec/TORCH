#!/usr/bin/env bash
# Provision the Kali VM: screenshot/tmux capture deps AND the recon + test toolchain the
# fingerprint router routes to, so a fingerprinted tool actually exists on the box.
#
# apt-first by design: Kali packages the whole ProjectDiscovery suite, which avoids the
# fragile `go install` path through the VPN tunnel (often egress-blocked) and installs the
# REAL ProjectDiscovery httpx as `httpx-toolkit` (the plain `httpx` apt/pip package is the
# Python HTTP library -- installing the toolkit is exactly the fix for the recurring
# "python httpx, not PD httpx" gap). Per-package tolerant: one unavailable name does not
# abort the batch. Idempotent (apt-get install is a no-op when already present).
#
#   bash vm-provision.sh          # install everything on the configured VM
#   bash vm-provision.sh --list   # print the toolset (no VM needed)
set -uo pipefail

# Screenshot / tmux-runner capture deps (this script's original purpose).
CAPTURE="tmux scrot xdotool imagemagick x11-utils xauth"
# Recon + test toolchain, Kali package names. httpx-toolkit = ProjectDiscovery httpx.
RECON="httpx-toolkit subfinder nuclei naabu dnsx katana amass gau gobuster ffuf \
feroxbuster dalfox gowitness arjun sqlmap hydra medusa nikto whatweb wpscan swaks \
jwt-tool trufflehog gitleaks seclists jq rlwrap"

if [ "${1:-}" = "--list" ]; then
  echo "capture deps:"; printf '  %s\n' $CAPTURE
  echo "recon/test toolchain (Kali apt):"; printf '  %s\n' $RECON
  exit 0
fi

if [ ! -f /root/vm.sh ] || [ ! -f /root/creds.txt ]; then
  echo "[note] Kali VM not configured (need /root/vm.sh + /root/creds.txt)."
  echo "       See docs/virtual-machine.md, then re-run: bash scripts/vm-provision.sh"
  exit 0
fi

# Build the remote installer as a self-contained script and push it via base64 (vm.sh
# does not forward stdin and quoting a per-package loop inline is brittle -- the vault
# already uses this base64-push pattern for shot.py).
REMOTE=$(cat <<REMOTE_EOF
#!/usr/bin/env bash
SUDO=""; [ "\$(id -u)" -eq 0 ] || SUDO="sudo"
\$SUDO DEBIAN_FRONTEND=noninteractive apt-get update -qq || echo "[warn] apt update failed"
for p in $CAPTURE $RECON; do
  if \$SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "\$p" >/dev/null 2>&1; then
    echo "  ok   \$p"
  else
    echo "  MISS \$p (not in repo or failed)"
  fi
done
# fallbacks for tools not always apt-packaged
if ! command -v trufflehog >/dev/null 2>&1; then
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | \$SUDO sh -s -- -b /usr/local/bin >/dev/null 2>&1 && echo "  trufflehog (installer)" || echo "  MISS trufflehog"
fi
# pwncat-cs: auto-PTY-stabilizing reverse-shell handler (preferred over raw nc for a web-RCE
# foothold; see ctf-box Phase 3). apt on newer Kali, else pipx/pip --user; tolerant either way.
if ! command -v pwncat-cs >/dev/null 2>&1; then
  \$SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq pwncat-cs >/dev/null 2>&1 && echo "  ok   pwncat-cs (apt)" \
    || { pipx install pwncat-cs >/dev/null 2>&1 && echo "  pwncat-cs (pipx)" \
    || { pip install --user --break-system-packages -q pwncat-cs >/dev/null 2>&1 && echo "  pwncat-cs (pip --user)" \
    || echo "  MISS pwncat-cs (raw nc + vm-stabilize.sh is the fallback)"; }; }
fi
if ! command -v jwt_tool >/dev/null 2>&1 && [ ! -x /usr/local/bin/jwt_tool ]; then
  [ -d /opt/jwt_tool ] || \$SUDO git clone -q https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null
  [ -f /opt/jwt_tool/jwt_tool.py ] && \$SUDO ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool && echo "  jwt_tool (git)" || echo "  MISS jwt_tool"
fi
# /opt/arsenal: canonical on-VM home for OUR helpers + fetched offensive tools. World-writable
# so the base64 push (below, from the vault side) and the model can drop scripts here.
\$SUDO mkdir -p /opt/arsenal && \$SUDO chmod 0777 /opt/arsenal
[ -f /opt/arsenal/pspy64 ] || { curl -sSfL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /opt/arsenal/pspy64 && chmod +x /opt/arsenal/pspy64 && echo "  arsenal pspy64" || echo "  MISS pspy64"; }
[ -f /opt/arsenal/linpeas.sh ] || { curl -sSfL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /opt/arsenal/linpeas.sh && chmod +x /opt/arsenal/linpeas.sh && echo "  arsenal linpeas.sh" || echo "  MISS linpeas.sh"; }
[ -f /opt/arsenal/winPEASx64.exe ] || { curl -sSfL https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe -o /opt/arsenal/winPEASx64.exe && echo "  arsenal winPEASx64.exe" || echo "  MISS winPEASx64.exe"; }
# Java deserialization: a JDK so gadgets can be BUILT (javac), + a best-effort ysoserial jar.
command -v javac >/dev/null 2>&1 || { \$SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq default-jdk-headless >/dev/null 2>&1 && echo "  jdk (javac)" || echo "  MISS jdk (need javac to build deser gadgets)"; }
[ -s /opt/arsenal/ysoserial.jar ] || { curl -sSfL -o /opt/arsenal/ysoserial.jar https://jitpack.io/com/github/frohoff/ysoserial/master/ysoserial-master.jar 2>/dev/null; [ "\$(stat -c%s /opt/arsenal/ysoserial.jar 2>/dev/null || echo 0)" -gt 100000 ] && echo "  arsenal ysoserial.jar" || { rm -f /opt/arsenal/ysoserial.jar; echo "  MISS ysoserial.jar (jitpack flaky; build a gadget by hand -> wiki payloads/deserialization 'Build the gadget yourself')"; }; }
REMOTE_EOF
)

echo "[..] provisioning toolchain on the VM (apt-first, per-package tolerant)"
B64=$(printf '%s' "$REMOTE" | base64 -w0)
bash /root/vm.sh "echo $B64 | base64 -d | bash"

# Seed /opt/arsenal with OUR vault-side helpers (base64 over the bridge, unconditional so a
# re-provision refreshes them): shot.py + capture.sh + any harness wordlists.
echo "[..] seeding /opt/arsenal with our helpers (shot.py, capture.sh, harness wordlists)"
HERE="$(cd "$(dirname "$0")" && pwd)"
for f in shot.py capture.sh; do
  [ -f "$HERE/$f" ] || continue
  bash /root/vm.sh "mkdir -p /opt/arsenal; printf %s '$(base64 -w0 "$HERE/$f")' | base64 -d > /opt/arsenal/$f && chmod +x /opt/arsenal/$f && echo '  arsenal $f'"
done
for wl in "$HERE"/wordlists/harness-*.txt; do
  [ -f "$wl" ] || continue
  bn="$(basename "$wl")"
  bash /root/vm.sh "printf %s '$(base64 -w0 "$wl")' | base64 -d > /opt/arsenal/$bn && echo '  arsenal $bn'"
done

echo "[ok] provisioning attempted. Verify installed binaries with:"
echo "     bash /root/vm.sh 'for t in httpx subfinder ffuf naabu dnsx katana gau dalfox arjun sqlmap swaks jwt_tool trufflehog gitleaks; do command -v \$t >/dev/null 2>&1 && echo \"ok \$t\" || echo \"MISSING \$t\"; done'"
echo "     (note: httpx-toolkit installs the binary as 'httpx'; if a name is MISSING, tune the package name for your Kali release.)"
