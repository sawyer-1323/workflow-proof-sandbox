#!/usr/bin/env bash
# Builds the sandbox inside an AGENT job, as the runner user (which has sudo),
# before any agent process exists.
#   uid `agent`:      runs the agent. No sudo, no capabilities, not in sudo, adm,
#                     docker, lxd or runner groups; no cron or at. Egress: only
#                     127.0.0.1:<MODEL_PROXY_PORT> (the model proxy). Nothing else,
#                     not even DNS: the agent needs no other host.
#   uid `modelproxy`: runs the model proxy only. Egress: only TCP 443 to the
#                     pinned IPv4 addresses of api.anthropic.com (resolved here,
#                     so it needs no DNS), plus replies on connections it accepted.
# Both uids: no IPv6 egress. Neither can read the runner's files, the other
# uid's /proc/<pid>/environ or /proc/<pid>/mem, or signal the other's processes.
# Usage: agent-sandbox.sh        Env: MODEL_PROXY_PORT (default 8787)
set -euo pipefail

port="${MODEL_PROXY_PORT:-8787}"
here="$(cd "$(dirname "$0")" && pwd)"

# 1. Users.
id agent >/dev/null 2>&1 || sudo useradd --create-home --shell /bin/bash --user-group agent
id modelproxy >/dev/null 2>&1 || sudo useradd --system --home-dir /var/lib/modelproxy --shell /usr/sbin/nologin --user-group modelproxy
for u in agent modelproxy; do
  for g in sudo adm docker lxd runner; do
    if id -nG "$u" | tr ' ' '\n' | grep -qx "$g"; then echo "::error::$u is in group $g"; exit 1; fi
  done
  if sudo -u "$u" -- sudo -n true 2>/dev/null; then echo "::error::$u can sudo"; exit 1; fi
done
echo "agent uid=$(id -u agent), modelproxy uid=$(id -u modelproxy); sudo denied for both (verified)"

# 2. Files: keep both uids out of the runner's home; no cron or at.
sudo chmod 0750 "$HOME"
echo runner | sudo tee /etc/cron.allow /etc/at.allow >/dev/null
sudo install -d -o agent -g agent -m 0700 /home/agent/work /home/agent/out /home/agent/task
sudo chmod 0700 /home/agent
sudo install -d -o modelproxy -g modelproxy -m 0700 /var/lib/modelproxy
sudo install -d -o root -g root -m 0755 /opt/modelproxy
sudo install -o root -g root -m 0644 "$here/model-proxy.js" /opt/modelproxy/model-proxy.js

# 3. Pin the model API addresses (runner-side DNS; neither sandbox uid resolves names).
getent ahostsv4 api.anthropic.com | awk '{print $1}' | sort -u > "$RUNNER_TEMP/anthropic-ips"
[ -s "$RUNNER_TEMP/anthropic-ips" ] || { echo "::error::cannot resolve api.anthropic.com"; exit 1; }
sudo install -o root -g root -m 0644 "$RUNNER_TEMP/anthropic-ips" /opt/modelproxy/anthropic-ips
echo "api.anthropic.com pinned to $(paste -sd, "$RUNNER_TEMP/anthropic-ips")"

# 4. Egress rules, per uid.
ua="$(id -u agent)"; um="$(id -u modelproxy)"
for c in AGENT_OUT MODELPROXY_OUT; do sudo iptables -N "$c" 2>/dev/null || sudo iptables -F "$c"; done
sudo iptables -A AGENT_OUT -o lo -p tcp -d 127.0.0.1 --dport "$port" -j ACCEPT
sudo iptables -A AGENT_OUT -j REJECT
sudo iptables -A MODELPROXY_OUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
while read -r ip; do sudo iptables -A MODELPROXY_OUT -p tcp -d "$ip" --dport 443 -j ACCEPT; done < "$RUNNER_TEMP/anthropic-ips"
sudo iptables -A MODELPROXY_OUT -j REJECT
for pair in "$ua:AGENT_OUT" "$um:MODELPROXY_OUT"; do
  uid="${pair%%:*}"; chain="${pair#*:}"
  sudo iptables -C OUTPUT -m owner --uid-owner "$uid" -j "$chain" 2>/dev/null \
    || sudo iptables -I OUTPUT 1 -m owner --uid-owner "$uid" -j "$chain"
  sudo ip6tables -C OUTPUT -m owner --uid-owner "$uid" -j REJECT 2>/dev/null \
    || sudo ip6tables -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
done
sudo iptables -S AGENT_OUT
sudo iptables -S MODELPROXY_OUT
echo "sandbox ready: agent -> 127.0.0.1:$port only; modelproxy -> api.anthropic.com:443 only"
