#!/usr/bin/env bash
# Network probe (T3.1 to T3.8). Runs AS THE AGENT USER inside the sandbox, after
# the model proxy has started. Every row must be REJECTED.
# Prints one line per row: <id> PASS|FAIL <what> <observed>. Exit 1 on any FAIL.
set -uo pipefail

port="${MODEL_PROXY_PORT:-8787}"
ip="$(head -n1 /opt/modelproxy/anthropic-ips)"
fail=0
row() { # id ok(0|1) what observed
  if [ "$2" -eq 0 ]; then echo "$1 PASS $3 ($4)"; else echo "$1 FAIL $3 ($4)"; fail=1; fi
}
tcp() { timeout 6 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }
code() { curl -sS -o /dev/null -m 8 -w '%{http_code}' "$@" 2>/dev/null; true; }

# T3.1 direct TCP to an external IP and port.
tcp 1.1.1.1 443; r=$?; row T3.1 $([ $r -ne 0 ] && echo 0 || echo 1) "direct TCP 1.1.1.1:443" "exit $r"
tcp 8.8.8.8 53; r=$?;  row T3.1 $([ $r -ne 0 ] && echo 0 || echo 1) "direct TCP 8.8.8.8:53" "exit $r"

# T3.2 direct HTTPS to the model API, bypassing the model proxy (pinned address, real SNI).
c="$(code --noproxy '*' --resolve "api.anthropic.com:443:$ip" https://api.anthropic.com/v1/messages)"
row T3.2 $([ "$c" = "000" ] && echo 0 || echo 1) "direct HTTPS api.anthropic.com via $ip" "http $c"
c="$(code --noproxy '*' https://api.anthropic.com/)"
row T3.2 $([ "$c" = "000" ] && echo 0 || echo 1) "direct HTTPS api.anthropic.com by name" "http $c"

# T3.3 IP literals.
for t in "https://$ip/" https://1.1.1.1/ http://93.184.215.14/; do
  c="$(code --noproxy '*' -k "$t")"; row T3.3 $([ "$c" = "000" ] && echo 0 || echo 1) "IP literal $t" "http $c"
done

# T3.4 IPv6.
c="$(code -6 --noproxy '*' 'https://[2606:4700:4700::1111]/')"
row T3.4 $([ "$c" = "000" ] && echo 0 || echo 1) "IPv6 HTTPS [2606:4700:4700::1111]" "http $c"
tcp ::1 "$port"; r=$?; row T3.4 $([ $r -ne 0 ] && echo 0 || echo 1) "IPv6 loopback to the proxy port" "exit $r"

# T3.5 DNS through an external resolver, and through the local stub.
for srv in 8.8.8.8 1.1.1.1 127.0.0.53; do
  if command -v dig >/dev/null; then
    timeout 8 dig +tries=1 +time=3 "@$srv" example.com >/dev/null 2>&1; r=$?
    out="$(timeout 8 dig +short +tries=1 +time=3 "@$srv" example.com 2>/dev/null | head -c 64)"
    row T3.5 $([ -z "$out" ] && echo 0 || echo 1) "DNS query to $srv" "exit $r"
  else
    row T3.5 1 "DNS query to $srv" "dig not installed; install dnsutils in install-tools.sh"
  fi
done
getent hosts example.com >/dev/null 2>&1; r=$?
row T3.5 $([ $r -ne 0 ] && echo 0 || echo 1) "system resolver lookup example.com" "exit $r"

# T3.6 unauthorized destinations through the (only) local proxy, the model proxy.
c="$(code -x "http://127.0.0.1:$port" https://example.com/)"
row T3.6 $([ "$c" = "000" ] && echo 0 || echo 1) "CONNECT example.com:443 via the model proxy" "http $c"
c="$(code -x "http://127.0.0.1:$port" http://example.com/)"
row T3.6 $([ "$c" = "403" ] || [ "$c" = "405" ] && echo 0 || echo 1) "absolute-URI GET via the model proxy" "http $c"
c="$(code -X POST -H 'Host: example.com' "http://127.0.0.1:$port//example.com/v1/messages" -d '{}')"
row T3.6 $([ "$c" = "403" ] && echo 0 || echo 1) "path-smuggled host via the model proxy" "http $c"

# T3.7 firewall and routing changes.
iptables -F OUTPUT >/dev/null 2>&1; r=$?; row T3.7 $([ $r -ne 0 ] && echo 0 || echo 1) "iptables -F" "exit $r"
sudo -n iptables -F OUTPUT >/dev/null 2>&1; r=$?; row T3.7 $([ $r -ne 0 ] && echo 0 || echo 1) "sudo iptables -F" "exit $r"
nft flush ruleset >/dev/null 2>&1; r=$?; row T3.7 $([ $r -ne 0 ] && echo 0 || echo 1) "nft flush ruleset" "exit $r"
ip route add blackhole 192.0.2.1 >/dev/null 2>&1; r=$?; row T3.7 $([ $r -ne 0 ] && echo 0 || echo 1) "ip route add" "exit $r"

# T3.8 listener or forwarder the model proxy would accept or use.
node -e "require('net').createServer().listen($port,'127.0.0.1').on('error',e=>{console.log(e.code);process.exit(0)}).on('listening',()=>{console.log('BOUND');process.exit(0)})" > /tmp/t38-bind 2>&1
b="$(cat /tmp/t38-bind)"; row T3.8 $([ "$b" = "EADDRINUSE" ] && echo 0 || echo 1) "bind the model proxy port" "$b"
node -e "let n=0;const s=require('net').createServer(c=>{n++;c.destroy()}).listen(18787,'127.0.0.1',()=>setTimeout(()=>{require('fs').writeFileSync('/tmp/t38-count',String(n));s.close()},8000))" &
sleep 1
code -X POST -H 'Host: 127.0.0.1:18787' -H 'X-Forwarded-Host: 127.0.0.1:18787' -H 'Content-Type: application/json' \
  "http://127.0.0.1:$port/v1/messages" -d '{"model":"not-allowlisted","max_tokens":1,"messages":[]}' >/dev/null
sleep 8
n="$(cat /tmp/t38-count 2>/dev/null || echo missing)"
row T3.8 $([ "$n" = "0" ] && echo 0 || echo 1) "agent listener on 127.0.0.1:18787 received connections from the proxy" "$n"
rm -f /tmp/t38-bind /tmp/t38-count

echo "== T3 result: $([ "$fail" -eq 0 ] && echo PASS || echo FAIL)"
exit "$fail"
