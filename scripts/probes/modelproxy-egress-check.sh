#!/usr/bin/env bash
# T3.8 (proxy side) and MP egress. Runs as the RUNNER user, which uses sudo to
# act as `modelproxy` for these checks only. Expected: modelproxy reaches only
# api.anthropic.com:443 at the pinned addresses; never a loopback listener,
# never another host, never IPv6.
set -uo pipefail

ip="$(head -n1 /opt/modelproxy/anthropic-ips)"
fail=0
row() { if [ "$2" -eq 0 ]; then echo "$1 PASS $3 ($4)"; else echo "$1 FAIL $3 ($4)"; fail=1; fi; }
as_mp() { sudo -u modelproxy -- "$@"; }

node -e "let n=0;const s=require('net').createServer(c=>{n++;c.destroy()}).listen(18788,'127.0.0.1',()=>setTimeout(()=>{require('fs').writeFileSync(process.env.RUNNER_TEMP+'/mp-count',String(n));s.close()},6000))" &
sleep 1
as_mp timeout 4 bash -c 'exec 3<>/dev/tcp/127.0.0.1/18788' 2>/dev/null; r=$?
sleep 6
row T3.8 $([ "$(cat "$RUNNER_TEMP/mp-count")" = "0" ] && [ $r -ne 0 ] && echo 0 || echo 1) "modelproxy uid connects to a loopback listener" "exit $r, accepted $(cat "$RUNNER_TEMP/mp-count")"

c="$(as_mp curl -sS -o /dev/null -m 8 -w '%{http_code}' https://example.com/ 2>/dev/null; true)"
row MP-egress $([ "$c" = "000" ] && echo 0 || echo 1) "modelproxy uid to example.com" "http $c"
c="$(as_mp curl -6 -sS -o /dev/null -m 8 -w '%{http_code}' 'https://[2606:4700:4700::1111]/' 2>/dev/null; true)"
row MP-egress $([ "$c" = "000" ] && echo 0 || echo 1) "modelproxy uid IPv6" "http $c"
c="$(as_mp curl -sS -o /dev/null -m 8 -w '%{http_code}' --resolve "api.anthropic.com:443:$ip" https://api.anthropic.com/ 2>/dev/null; true)"
row MP-egress $([ "$c" != "000" ] && echo 0 || echo 1) "modelproxy uid to api.anthropic.com at the pinned address (must work)" "http $c"

echo "== modelproxy egress result: $([ "$fail" -eq 0 ] && echo PASS || echo FAIL)"
exit "$fail"
