# coppersmith-curve  Zero-Trust Identity

**CTF:** polriCTF 2026  
**Category:** Crypto  
**Points:** 100  
**Solves:** 92  
**Flag:** `polriCTF26{hastad_broadcast_leaks_the_ecdsa_nonce_and_the_curve_falls}`

---

## deskripsi

> Sebuah layanan "Zero-Trust Identity". Untuk login sebagai admin kamu harus menyodorkan tanda tangan ECDSA secp256k1 `(r, s)` yang valid atas pesan persis `b"admin=true"`. Layanan ini hanya mau menandatangani heartbeat miliknya sendiri untukmu. Selebihnya, itu masalahmu.
>
> **Akses:** `nc 18.143.187.232 9008`

judulnya "coppersmith-curve" tapi pas dibuka… ya gak pure coppersmith sih. lebih ke hastad + ecdsa nonce leak. naming is marketing I guess.

---

## recon

connect ke service, dapet banner + menu:

```
[1] mirror seed to replicas   (prints N1,e,C1 / N2,e,C2 / N3,e,C3)
[2] leak heartbeat signature  (prints msg, r, s)
[3] admin login               (submit r, s over "admin=true")
[4] show pubkey Q + PRNG source
[5] quit
```

option `[4]` yang paling berguna, karena dia spill implementasi PRNG-nya:

```python
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
```

plus keterangan penting:

- seed di-broadcast pake RSA `e=3` ke 3 replica (menu `[1]`)
- heartbeat signature di menu `[2]` pake **FIRST** `next_scalar()` sebagai nonce `k`
- padding RSA-nya deterministic:

```
m = int( b"ZTRUST-IDENTITY-SEED-v1::" || seed(32B) || b"\x00"*8 || (b"ZT")*80 )
```

jadi rantai attack-nya udah keliatan dari sini:

```
RSA e=3 broadcast → ambil seed → replay PRNG → dapet k → recover d → forge admin sig
```

---

## step 1  hastad broadcast

menu `[1]` ngasih 3 ciphertext dengan `e = 3` dan plainteks yang **sama** (padding-nya identik per node). classic Hastad.

asalkan `m^3 < N1*N2*N3` (yang hampir pasti, karena `m` cuma ~1800 bit dan modulus 2048-bit), CRT langsung ngasih `m^3` exact, trus integer cube root.

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

x = crt(Cs, Ns)   # = m^3
m = iroot(x, 3)
assert m**3 == x
```

parse padding-nya:

```python
prefix = b"ZTRUST-IDENTITY-SEED-v1::"
suffix = b"\x00"*8 + b"ZT"*80
raw = long_to_bytes(m, len(prefix) + 32 + len(suffix))
seed_bytes = raw[len(prefix):len(prefix)+32]
seed = bytes_to_long(seed_bytes)
```

seed ketemu. gampang.

---

## step 2  replay PRNG, ambil k

PRNG-nya deterministic dari seed, dan challenge bilang heartbeat pake scalar **pertama**. jadi:

```python
rng = NonceRNG(seed)
k = rng.next_scalar()
```

verify dulu biar ga malu:

```python
R = k * G
assert (R.x() % n) == r_heartbeat
```

match. nice.

---

## step 3  recover private key

ECDSA:

\[
s \equiv k^{-1}(z + r\cdot d) \pmod n
\]

jadi:

\[
d \equiv r^{-1}(s\cdot k - z) \pmod n
\]

`z` = `SHA256(b"ztrust-session-heartbeat")` diinterpretasi sebagai integer (secp256k1 order 256-bit, jadi full hash, gak kepotong).

```python
z = bytes_to_long(sha256(msg_hb).digest()) % n
d = (inverse(r, n) * (s * k - z)) % n

assert (d * G).x() == Qx   # cocok sama pubkey dari menu [4]
```

private key kebuka.

---

## step 4  forge + login

tinggal sign pesan yang diminta:

```python
msg = b"admin=true"
k2 = random.randrange(1, n)   # k bebas, asal valid
r2 = (k2 * G).x() % n
s2 = (inverse(k2, n) * (z_admin + r2 * d)) % n
```

submit di menu `[3]`:

```
r> <r2>
s> <s2>
access granted. flag: polriCTF26{hastad_broadcast_leaks_the_ecdsa_nonce_and_the_curve_falls}
```

---

## full solver (ringkas)

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
    s.sendall(opt + (b"" if opt.endswith(b"\n") else b"\n"))
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

def iroot(n, k=3):
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x**(k - 1)) // k
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

m = iroot(crt(Cs, Ns), 3)
assert m**3 == crt(Cs, Ns)

prefix = b"ZTRUST-IDENTITY-SEED-v1::"
suffix = b"\x00"*8 + b"ZT"*80
raw = long_to_bytes(m, len(prefix) + 32 + len(suffix))
seed = bytes_to_long(raw[len(prefix):len(prefix)+32])

k = NonceRNG(seed).next_scalar()
assert (k * G).x() % n == r_hb

d = (inverse_mod(r_hb, n) * (s_hb * k - hmsg(msg_hb))) % n
assert (d * G).x() == Qx
print("[+] d recovered:", d)

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

---

## takeaway

inti challenge-nya bukan di curve-nya, tapi di **key management yang ampas**:

1. seed yang sama di-encrypt ke 3 modulus dengan `e=3` + padding identik → Hastad free win
2. nonce ECDSA diturunin dari seed itu secara deterministic → `k` known
3. known nonce = known private key. selesai.

kalau salah satu aja diubah (padding beda per node / OAEP, atau `k` beneran random / RFC6979), chain-nya putus. di sini semuanya disusun biar domino.

flagnya juga spoiler sih:

```
polriCTF26{hastad_broadcast_leaks_the_ecdsa_nonce_and_the_curve_falls}
```

---

## referensi

- Hastad's broadcast attack — Boneh, *Twenty Years of Attacks on the RSA Cryptosystem*
- ECDSA nonce reuse / known nonce → private key recovery (same math as nonce reuse across two messages)
- secp256k1 order & generator (standard)

"ditulis oleh aku gw, Salam pria solo!"
