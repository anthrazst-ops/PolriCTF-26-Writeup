# crackme_polri ~ SMC, modulo 5, trus flag kebuka dari belakang

> **CTF:** polriCTF 2026  
> **Challenge:** crackme_polri  
> **Category:** Reverse  
> **Solved:** 2026-08-01  
> **Author:** gw / De4dsec01  
> **Tag:** SMC, mmap, mprotect, XOR rolling key, ROL/ROR

---

## awalnya: ELF stripped, IDA bingung

Dapet biner `crackme_polri` — ELF 64-bit, stripped. Buka di IDA Free, langsung terasa aneh: area yang keliatan kayak fungsi checker isinya sampah / pola aneh, bukan logic flag yang bersih.

Pas ditelusuri lebih dalam, ternyata ini **Self-Modifying Code (SMC)**. Fungsi pengecek flag-nya **terenkripsi di memori**, baru didekripsi pas runtime lewat `mmap()` + `mprotect()`.

Jadi static analysis doang nggak cukup — harus liat gimana dia nge-decrypt dirinya sendiri dulu.

---

## jejak di IDA: `0xCCCCCCCCCCCCCCCD`

Di sekitar `loc_1270` keliatan konstanta:

```
0xCCCCCCCCCCCCCCCD
```

Ini pola klasik optimasi GCC buat **modulo 5** (`i % 5`). Compiler sering ganti division/modulo pake magic multiply.

Artinya kunci XOR-nya kemungkinan **5 byte**, diulang-ulang (rolling key).

---

## ambil payload, dekripsi

Gue ambil **352 byte** encrypted payload dari binernya, trus dekripsi pake kunci 5-byte (hasil dari analisis modulo / key schedule SMC-nya) sampai dapet blob bersih:

```
fungsi_rahasia.bin
```

Disassemble pake `objdump`:

```bash
objdump -D -b binary -m i386:x86-64 fungsi_rahasia.bin | less
```

Dari situ baru keliatan logic aslinya.

---

## logic checker (3 tahap)

Input **16 karakter** diolah berurutan sebelum dibandingkan ke array ciphertext:

1. **XOR** sama `0x5A`
2. **Tambah** `i * 3` (i = index 0..15)
3. **ROL 2** (rotate left 2 bit)

Kurang lebih:

```text
out[i] = ROL2( (in[i] ^ 0x5A) + (3 * i) )
```

Ciphertext yang di-compare:

```python
encrypted_flag = [
    0x24, 0x68, 0x7C, 0x38, 0xDD, 0x60, 0x5C, 0x78,
    0x0A, 0x80, 0xDC, 0x2E, 0x3A, 0xF4, 0x96, 0xA2,
]
```

---

## reverse dari belakang

Balikin urutannya:

1. **ROR 2** (balikin ROL 2)
2. **kurang** `i * 3`
3. **XOR** `0x5A` lagi

```python
encrypted_flag = [
    0x24, 0x68, 0x7C, 0x38, 0xDD, 0x60, 0x5C, 0x78,
    0x0A, 0x80, 0xDC, 0x2E, 0x3A, 0xF4, 0x96, 0xA2,
]

flag = ""
for i, val in enumerate(encrypted_flag):
    # balikin ROL 2 -> ROR 2
    val = ((val >> 2) | (val << 6)) & 0xFF
    # balikin + (i * 3)
    val = (val - (3 * i)) & 0xFF
    # balikin XOR 0x5A
    val ^= 0x5A
    flag += chr(val)

print(f"Flag: polriCTF26{{{flag}}}")
```

Jalanin → flag ketemu.

---

## ringkasan

```
1. ELF stripped + SMC (decrypt runtime via mmap/mprotect)
2. Magic 0xCCCCCCCCCCCCCCCD → hint modulo 5 → XOR key 5 byte rolling
3. Dump 352B payload → decrypt → fungsi_rahasia.bin
4. objdump → logic: XOR 0x5A → + i*3 → ROL 2
5. Reverse: ROR 2 → - i*3 → XOR 0x5A
6. flag
```

---

## flag

```
polriCTF26{SMC_1S_S0_C00L!!}
```

---

## catatan pribadi

- SMC bikin static view di IDA keliatan “rusak” — jangan panik, cari `mprotect` / `mmap` / writable+executable region.
- Magic constant GCC sering jadi cheat code buat nebak operasi aritmetika (`% 5`, `/ 3`, dll).
- Transform flag-nya pendek (3 step), jadi paling aman reverse dari ciphertext, bukan brute.

---

*De4dsec01 · anthrazstclaa · 2026-08-01*  
*salam pria solo*
