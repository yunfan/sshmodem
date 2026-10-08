#!/usr/bin/env bash
# 端到端冒烟：用 `smodem -- smodem serve` 直连（不经 ssh），curl 走 socks5h。
# 覆盖：小请求、域名解析、大文件（流控）、并发、拒绝连接、四种编码。
set -u
BIN="${1:-./zig-out/bin/smodem}"
PORT=${SMODEM_E2E_PORT:-11080}
HTTP=$(( 20000 + (RANDOM % 20000) ))
FAIL=0
TMP=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$TMP"' EXIT

command -v curl >/dev/null || { echo "SKIP: curl not found"; exit 0; }
command -v python3 >/dev/null || { echo "SKIP: python3 not found"; exit 0; }

head -c 3000000 /dev/urandom > "$TMP/big.bin"
truncate -s 1G "$TMP/huge.bin"   # 稀疏文件，不占盘；给"中途取消"用
( cd "$TMP" && python3 -m http.server "$HTTP" --bind 127.0.0.1 >/dev/null 2>&1 ) &
sleep 1

check() { # desc expected_code url [outfile]
  local desc="$1" want="$2" url="$3" out="${4:-/dev/null}"
  local code
  code=$(curl -sS -m 20 -x "socks5h://127.0.0.1:$PORT" "$url" -o "$out" -w "%{http_code}" 2>/dev/null)
  if [ "$code" = "$want" ]; then echo "  ok  $desc ($code)"; else echo "  FAIL $desc (got $code want $want)"; FAIL=1; fi
}

for enc in auto b64 esc raw b32; do
  echo "== encoding=$enc =="
  if [ "$enc" = auto ]; then
    "$BIN" -q -p "$PORT" -- "$BIN" serve >"$TMP/sm.log" 2>&1 &
  else
    "$BIN" -q -p "$PORT" --encoding "$enc" -- "$BIN" serve --encoding "$enc" >"$TMP/sm.log" 2>&1 &
  fi
  SM=$!
  sleep 1
  check "small ip"   200 "http://127.0.0.1:$HTTP/big.bin" "$TMP/o1"
  check "domain"     200 "http://localhost:$HTTP/big.bin" "$TMP/o2"
  if ! cmp -s "$TMP/big.bin" "$TMP/o2"; then echo "  FAIL big file mismatch"; FAIL=1; else echo "  ok  big file 3MB matches"; fi
  # 并发
  okc=0; for i in $(seq 1 15); do
    c=$(curl -sS -m 15 -x "socks5h://127.0.0.1:$PORT" "http://localhost:$HTTP/" -o /dev/null -w "%{http_code}" 2>/dev/null)
    [ "$c" = "200" ] && okc=$((okc+1))
  done
  if [ "$okc" = 15 ]; then echo "  ok  concurrency 15/15"; else echo "  FAIL concurrency $okc/15"; FAIL=1; fi
  kill $SM 2>/dev/null; wait $SM 2>/dev/null
done

echo "== refused =="
"$BIN" -q -p "$PORT" -- "$BIN" serve >"$TMP/sm.log" 2>&1 &
SM=$!; sleep 1
rc=$(curl -sS -m 8 -x "socks5h://127.0.0.1:$PORT" "http://127.0.0.1:9/" -o /dev/null -w "%{http_code}" 2>/dev/null)
if [ "$rc" = "000" ]; then echo "  ok  refused relayed"; else echo "  note refused code=$rc"; fi
kill $SM 2>/dev/null; wait $SM 2>/dev/null

echo "== armor + key =="
"$BIN" -q -p "$PORT" --armor --key e2e-secret -- "$BIN" serve >"$TMP/sm.log" 2>&1 &
SM=$!; sleep 1
check "armor small" 200 "http://127.0.0.1:$HTTP/big.bin" "$TMP/oa"
grep -q "send=b32 recv=b32" "$TMP/sm.log" && echo "  ok  armor negotiated B32" || { echo "  FAIL armor not B32"; cat "$TMP/sm.log"; FAIL=1; }
kill $SM 2>/dev/null; wait $SM 2>/dev/null

echo "== udp associate =="
"$BIN" -q -p "$PORT" -- "$BIN" serve >"$TMP/sm.log" 2>&1 &
SM=$!; sleep 1
if python3 scripts/udp_e2e.py "$PORT" >/tmp/udp.out 2>&1; then echo "  ok  udp associate echo"; else echo "  FAIL udp associate"; cat /tmp/udp.out; FAIL=1; fi
kill $SM 2>/dev/null; wait $SM 2>/dev/null

echo "== udp forward =="
UECHO=$(( 20000 + RANDOM % 20000 )); LFWD=$(( 20000 + RANDOM % 20000 ))
python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',$UECHO))
while True:
    d,a=s.recvfrom(2048); s.sendto(b'E:'+d,a)
" &
UP=$!; sleep 1
"$BIN" -q -p "$PORT" --udp $LFWD:127.0.0.1:$UECHO -- "$BIN" serve >"$TMP/sm.log" 2>&1 &
SM=$!; sleep 1
if python3 -c "
import socket
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.settimeout(5)
u.sendto(b'ping',('127.0.0.1',$LFWD)); d,_=u.recvfrom(2048)
assert d==b'E:ping', d
print('ok')
" >/dev/null 2>&1; then echo "  ok  udp static forward"; else echo "  FAIL udp static forward"; FAIL=1; fi
kill $SM $UP 2>/dev/null; wait $SM 2>/dev/null

echo "== robustness =="
"$BIN" -q -p "$PORT" -- "$BIN" serve >"$TMP/sm.log" 2>&1 &
SM=$!; sleep 1
# 中途取消的下载不能把会话窗口吃光（协议 §7.4）：之前约 20 次后隧道静默卡死。
for i in $(seq 1 40); do curl -s -m 0.3 -x "socks5h://127.0.0.1:$PORT" "http://127.0.0.1:$HTTP/huge.bin" -o /dev/null; done
check "after 40 aborted downloads" 200 "http://127.0.0.1:$HTTP/big.bin" "$TMP/or"
# 正常关闭的连接必须回收 fd（Linux /proc）。
if [ -d /proc/$SM/fd ]; then
  before=$(ls /proc/$SM/fd | wc -l)
  for i in $(seq 1 50); do curl -s -m 5 -x "socks5h://127.0.0.1:$PORT" "http://127.0.0.1:$HTTP/" -o /dev/null; done
  sleep 1; after=$(ls /proc/$SM/fd | wc -l)
  if [ $((after - before)) -le 2 ]; then echo "  ok  no fd leak ($before -> $after)"; else echo "  FAIL fd leak ($before -> $after after 50 requests)"; FAIL=1; fi
fi
kill $SM 2>/dev/null; wait $SM 2>/dev/null

echo "== push mode =="
mkdir -p "$TMP/fakessh"
cat > "$TMP/fakessh/ssh" <<'EOF'
#!/bin/sh
for a in "$@"; do last="$a"; done
exec sh -c "$last"
EOF
chmod +x "$TMP/fakessh/ssh"
PATH="$TMP/fakessh:$PATH" "$BIN" -q -p "$PORT" --push "$BIN" dummy >"$TMP/sm.log" 2>&1 &
SM=$!; sleep 3
check "push proxied" 200 "http://127.0.0.1:$HTTP/big.bin" "$TMP/op"
kill $SM 2>/dev/null; wait $SM 2>/dev/null

if [ "$FAIL" = 0 ]; then echo "E2E: ALL PASS"; else echo "E2E: FAILURES"; fi
exit $FAIL
