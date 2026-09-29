import socket, struct, threading, sys, time

PROXY=("127.0.0.1", int(sys.argv[1]))

# UDP echo target
echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
echo.bind(("127.0.0.1", 0))
ep = echo.getsockname()[1]
def echo_loop():
    while True:
        d,a = echo.recvfrom(4096)
        echo.sendto(b"ECHO:"+d, a)
threading.Thread(target=echo_loop, daemon=True).start()

# 1) TCP control: greeting + UDP ASSOCIATE
t = socket.socket(); t.connect(PROXY)
t.sendall(bytes([5,1,0])); assert t.recv(2)==bytes([5,0]), "greeting"
# request UDP ASSOCIATE, addr 0.0.0.0:0
t.sendall(bytes([5,3,0,1,0,0,0,0,0,0]))
rep=t.recv(10)
assert rep[1]==0, "assoc rep=%d"%rep[1]
relay_ip=".".join(str(b) for b in rep[4:8]); relay_port=struct.unpack("!H",rep[8:10])[0]
# 2) UDP send through relay
u=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(4)
# SOCKS5 UDP header: RSV RSV FRAG ATYP=1 ip port + data → target = 127.0.0.1:ep
hdr=bytes([0,0,0,1,127,0,0,1])+struct.pack("!H",ep)
u.sendto(hdr+b"ping-over-udp", (relay_ip, relay_port))
data,_=u.recvfrom(4096)
# strip returned SOCKS5 UDP header (10 bytes for ipv4)
payload=data[10:]
print("GOT:", payload)
assert payload==b"ECHO:ping-over-udp", payload
print("UDP E2E OK")
