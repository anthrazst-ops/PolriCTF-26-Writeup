# coppersmith-curve ~ dari RSA broadcast sampe private key ECDSA kebuka

> **CTF:** polriCTF 2026  
> **Target:** `18.143.187.232`  
> **Port:** `9008` (Zero-Trust Identity)  
> **Solved:** 2026-08-01  
> **Author:** gw / tim (gw doang sih ini)  
> **Tag:** Hastad broadcast, ECDSA known-nonce, xorshift PRNG, secp256k1  
> **Points:** 100 · **Solves:** 92

---

## awalnya: nc doang, menu aneh

Jadi tantangannya bilang: layanan "Zero-Trust Identity". Buat login admin harus sodorin tanda tangan ECDSA secp256k1 `(r, s)` yang valid atas pesan persis `b"admin=true"`. Layanan cuma mau nandatanganin heartbeat miliknya sendiri. Selebihnya, masalah kita.

Aksesnya:

```bash
nc 18.143.187.232 9008
```

(di mesin gw `nc` nggak ada, jadi pake python socket — sama aja.)

Banner-nya:

```
=================================================================
  coppersmith-curve   (polriCTF 2026)   [ Zero-Trust Identity ]
  Authenticate as admin: present a valid secp256k1 ECDSA signature
  (r, s) over the exact message  b"admin=true".
  The service will sign its OWN heartbeat for you, and mirror your
  session seed to three identity replicas (RSA, e=3).
=================================================================
```

Judulnya "coppersmith-curve" tapi dari banner aja udah kebaca: **RSA e=3 ke tiga replica** + **ECDSA**. Ini bukan pure Coppersmith sih. Lebih ke Hastad + nonce leak. Naming is marketing I guess.

Menu-nya:

```
[1] mirror seed to replicas   (prints N1,e,C1 / N2,e,C2 / N3,e,C3)
[2] leak heartbeat signature  (prints msg, r, s)
[3] admin login               (submit r, s over "admin=true")
[4] show pubkey Q + PRNG source
[5] quit
```

Option `[4]` yang paling berguna. Gw pencet itu duluan.

---

## option [4]: spill PRNG + padding

Keluarannya kurang lebih gini:

```
Qx = ...
Qy = ...
# secp256k1 params are standard. Public key Q printed above.
# Nonce PRNG (seeded from the per-connection `seed`):
class NonceRNG:
    MASK = (1<<128)-1
    def __init__(self, seed):
        h = sha256(long_to_bytes(seed)).digest()
        self.s = bytes_to_long(h[:16]) | 1
    def _step(self):
        x = self.s
        x ^= (x << 13) & MASK
        x ^= (x >> 7)
        x ^= (x << 17) & MASK
        self.s = x & MASK
        return self.s
    def next_scalar(self):
        hi = self._step(); lo = self._step()
        return ((hi<<128)|lo) % N
# seed is RSA-broadcast (e=3) in menu [1]; the heartbeat signature in
# menu [2] uses the FIRST next_scalar() as its nonce k.
# RSA padding:  m = int( b"ZTRUST-IDENTITY-SEED-v1::" || seed(32B) ||
#                        b"\x00"*8 || (b"ZT")*80 )   -- identical per node.
```

**Ini gold.** Challenge-nya nge-spill:

1. seed di-broadcast RSA `e=3` ke 3 node, **padding identik**
2. heartbeat di menu `[2]` pake **FIRST** `next_scalar()` sebagai nonce `k`
3. format padding deterministic: prefix + seed 32 byte + suffix

Jadi rantai attack-nya udah kebayang dari sini:

```
RSA e=3 broadcast → ambil seed → replay PRNG → dapet k
→ recover d dari (r,s,k,z) → forge sig admin=true → login
```

---

## step 1  Hastad broadcast (menu [1])

Menu `[1]` ngasih tiga pasang `(N, e=3, C)` dengan plainteks yang **sama**. Classic Hastad.

Asalkan `m³ < N1·N2·N3` (hampir pasti — `m` cuma ~1800 bit, modulus 2048-bit), CRT langsung ngasih `m³` exact, trus integer cube root.

```python
def crt(rems, mods):
    M = 1
    for m in mods:
        M *= m
    x = 0
    for a, m in zip(rems, mods):
        Mi = M // m
        x += a * Mi * inverse(Mi, m)
    return x % M

def iroot(n, k=3):
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // (x ** (k - 1))) // k
        if y >= x:
            return x
        x = y

x = crt([C1, C2, C3], [N1, N2, N3])  # = m^3
m = iroot(x, 3)
assert m ** 3 == x
```

Parse padding:

```python
prefix = b"ZTRUST-IDENTITY-SEED-v1::"
suffix = b"\x00" * 8 + b"ZT" * 80
raw = long_to_bytes(m, len(prefix) + 32 + len(suffix))
assert raw.startswith(prefix) and raw.endswith(suffix)
seed_bytes = raw[len(prefix):len(prefix) + 32]
seed = bytes_to_long(seed_bytes)
```

Seed ketemu. Gampang. (Di run gw: `m` bitlen 1799, seed 32 byte clean.)

---

## step 2  replay PRNG, ambil k (menu [2])

PRNG-nya deterministic dari seed. Challenge bilang heartbeat pake scalar **pertama**. Jadi:

```python
rng = NonceRNG(seed)
k = rng.next_scalar()
```

Verify biar nggak malu:

```python
R = k * G   # G = secp256k1 generator
assert (R.x() % n) == r_heartbeat
```

**Match.** Berarti `k` bener.

Heartbeat messagenya:

```
msg = ztrust-session-heartbeat
r = <besar>
s = <besar>
```

---

## step 3  recover private key d

ECDSA klasik:

```
s ≡ k⁻¹ (z + r·d)  (mod n)
```

jadi:

```
d ≡ r⁻¹ (s·k − z)  (mod n)
```

`z` = SHA256 dari message, diinterpretasi sebagai integer. Order secp256k1 256-bit, jadi full hash, nggak kepotong.

```python
z = bytes_to_long(sha256(b"ztrust-session-heartbeat").digest()) % n
d = (inverse(r, n) * (s * k - z)) % n

# cek ke pubkey dari menu [4]
assert (d * G).x() == Qx
assert (d * G).y() == Qy
```

**Private key kebuka.** Satu sesi, beres.

---

## step 4  forge admin + login (menu [3])

Tinggal sign pesan yang diminta. `k` bebas asal valid:

```python
msg = b"admin=true"
k2 = bytes_to_long(os.urandom(32)) % n
r2 = (k2 * G).x() % n
s2 = (inverse(k2, n) * (z_admin + r2 * d)) % n
```

Submit di menu `[3]`:

```
r> <r2>
s> <s2>
access granted. flag: polriCTF26{hastad_broadcast_leaks_the_ecdsa_nonce_and_the_curve_falls}
```

**Dapet.**

---

## full solver (yang gw pake)

```python
#!/usr/bin/env python3
import socket, time, select, re, hashlib, os
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod

HOST, PORT = "18.143.187.232", 9008
curve, n, G = SECP256k1, SECP256k1.order, SECP256k1.generator

def recv_idle(s, idle=0.6, total=12):
    s.setblocking(0)
    buf, start, last = b"", time.time(), time.time()
    while time.time() - start < total:
        r, _, _ = select.select([s], [], [], 0.15)
        if r:
            try:
                d = s.recv(1 << 16)
                if not d: break
                buf += d; last = time.time()
            except BlockingIOError:
                pass
        elif buf and time.time() - last > idle:
            break
    return buf

def send_opt(s, opt):
    s.sendall(opt if opt.endswith(b"\n") else opt + b"\n")
    return recv_idle(s)

def pint(label, t):
    return int(re.search(rf"{label}\s*=\s*(\d+)", t).group(1))

def crt(rems, mods):
    M = 1
    for m in mods: M *= m
    x = 0
    for a, m in zip(rems, mods):
        Mi = M // m
        x += a * Mi * inverse(Mi, m)
    return x % M

def iroot(val, k=3):
    x = 1 << ((val.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + val // (x ** (k - 1))) // k
        if y >= x: return x
        x = y

class NonceRNG:
    MASK = (1 << 128) - 1
    def __init__(self, seed):
        h = hashlib.sha256(long_to_bytes(seed)).digest()
        self.s = bytes_to_long(h[:16]) | 1
    def _step(self):
        x = self.s
        x ^= (x << 13) & self.MASK
        x ^= x >> 7
        x ^= (x << 17) & self.MASK
        self.s = x & self.MASK
        return self.s
    def next_scalar(self):
        return ((self._step() << 128) | self._step()) % n

def hmsg(m):
    return bytes_to_long(hashlib.sha256(m).digest()) % n

s = socket.create_connection((HOST, PORT), timeout=15)
recv_idle(s)

out4 = send_opt(s, b"4").decode()
Qx, Qy = pint("Qx", out4), pint("Qy", out4)

out2 = send_opt(s, b"2").decode()
msg_hb = re.search(r"msg\s*=\s*(.+)", out2).group(1).strip().encode()
r_hb, s_hb = pint("r", out2), pint("s", out2)

out1 = send_opt(s, b"1").decode()
Ns = [pint("N1", out1), pint("N2", out1), pint("N3", out1)]
Cs = [pint("C1", out1), pint("C2", out1), pint("C3", out1)]

m3 = crt(Cs, Ns)
m = iroot(m3, 3)
assert m ** 3 == m3

prefix = b"ZTRUST-IDENTITY-SEED-v1::"
suffix = b"\x00" * 8 + b"ZT" * 80
raw = long_to_bytes(m, len(prefix) + 32 + len(suffix))
seed = bytes_to_long(raw[len(prefix):len(prefix) + 32])

k = NonceRNG(seed).next_scalar()
assert (k * G).x() % n == r_hb

d = (inverse_mod(r_hb, n) * (s_hb * k - hmsg(msg_hb))) % n
assert (d * G).x() == Qx and (d * G).y() == Qy
print("[+] d recovered")

admin = b"admin=true"
while True:
    k2 = bytes_to_long(os.urandom(32)) % n
    if k2: break
r2 = (k2 * G).x() % n
s2 = (inverse_mod(k2, n) * (hmsg(admin) + r2 * d)) % n

send_opt(s, b"3")
s.sendall(f"{r2}\n".encode()); time.sleep(0.3); recv_idle(s, total=3)
s.sendall(f"{s2}\n".encode()); time.sleep(0.3)
print(recv_idle(s, idle=1.0, total=5).decode())
```

Deps: `pip install pycryptodome ecdsa`

---

## ringkasan eksploitasi

```
1. Menu [4] → baca PRNG + format padding + pubkey Q
2. Menu [1] → 3 ciphertext RSA e=3, plainteks sama
3. Hastad (CRT + cube root) → recover m → parse seed 32B
4. Replay NonceRNG(seed) → k = next_scalar() pertama
5. Menu [2] → ambil (r,s) heartbeat, verify kG.x == r
6. d = r⁻¹ (s·k − z) mod n → cocok sama Q
7. Forge ECDSA atas b"admin=true"
8. Menu [3] → submit (r,s) → flag
```

---

## flag

```
polriCTF26{hastad_broadcast_leaks_the_ecdsa_nonce_and_the_curve_falls}
```

---

## catatan pribadi

- Awalnya dari judul "coppersmith-curve" gw kira bakalan Franklin-Reiter / stereotypic Coppersmith yang ribet. Ternyata enggak — Hastad polos + known nonce.
- Key management-nya yang ampas, bukan curvenya:
  - seed yang sama di-encrypt ke 3 modulus pake `e=3` + padding identik → Hastad free win
  - nonce ECDSA diturunin dari seed itu secara deterministic → `k` known
  - known nonce = known private key. Selesai.
- Kalau salah satu aja diubah (padding beda per node / OAEP, atau `k` beneran random / RFC6979), chain-nya putus. Di sini semuanya disusun biar domino.
- Flagnya juga spoiler sih. Marketing team challenge-nya jujur banget.
- Hal kecil yang bikin sempet panik sebentar: `long_to_bytes(seed)` vs fixed 32-byte. Di kasus ini seed full 32B jadi nggak ada leading-zero issue. Kalau seed kecil, hati-hati — PRNG hash-nya ikut kepotong.

---

*Ditulis oleh aku gw, salam pria solo! , 2026-08-01*

*Tools: python3, pycryptodome, ecdsa, socket mentah (nc nggak keinstall)*
