# AksesLab

AksesLab adalah CLI JavaScript untuk menguji rancangan aturan akses. Gunakan sebelum mengimplementasikan izin seperti akses dokumen milik sendiri, akses lintas unit, atau akses pengguna yang memiliki beberapa role.

## Fitur

1. **Validasi kebijakan JSON.** Periksa nama role, resource, aksi, relasi, properti ganda, dan siklus pewarisan.
2. **Jelaskan keputusan akses.** Lihat role efektif, aturan yang cocok, dan alasan `allow` atau `deny` untuk satu skenario.
3. **Audit seluruh kombinasi dalam cakupan pemeriksaan.** Uji ekspektasi terhadap kombinasi role dan relasi, lalu tampilkan contoh pelanggaran dengan gabungan role paling kecil lebih dahulu.
4. **Bandingkan dua versi kebijakan.** Temukan izin baru dan izin yang dicabut. Keluaran JSON dan kode keluar bisa dipakai dalam CI.

## Instalasi

Ekstrak ZIP, buka terminal di direktori yang memuat `package.json`, lalu gunakan Node.js 20 atau lebih baru. Program memakai modul bawaan Node.js sehingga bisa langsung dijalankan.

```powershell
node --version
node src/cli.js --help
```

## Coba alur lengkap

```powershell
node src/cli.js validate examples/kebijakan-aman.json
node src/cli.js audit examples/kebijakan-aman.json
node src/cli.js diff examples/kebijakan-aman.json examples/kebijakan-longgar.json --limit 1
node src/cli.js explain examples/kebijakan-longgar.json --resource dokumen --action baca --role wali --role koordinator --same-unit
```

Kebijakan contoh yang aman lolos lima pemeriksaan dengan 27 dari 87 skenario tercakup. Versi longgar menghapus penolakan eksplisit untuk wali yang membaca dokumen milik orang lain. Wali dengan role tambahan `asisten` mendapat izin lewat aturan baca satu unit. Role `koordinator` juga dapat memicu izin itu karena mewarisi `asisten`.

Keluaran perintah `diff` di atas memperlihatkan temuan berikut.

```text
87 skenario · 3 izin baru · 0 izin dicabut · 84 tetap
Izin baru · dokumen/baca · asisten + wali · owner=false · sameUnit=true · deny → allow
```

Audit versi longgar dan simpan hasilnya sebagai JSON.

```powershell
node src/cli.js audit examples/kebijakan-longgar.json --limit 2 --json > hasil-audit.json
```

`--limit` mengatur jumlah contoh per pemeriksaan untuk `audit` dan per arah perubahan untuk `diff`. Rentangnya 0 sampai 20 dengan nilai bawaan 5. Jumlah pelanggaran dan keputusan yang berubah tetap dihitung seluruhnya. Untuk `explain`, ulangi `--role` untuk menambahkan role. Flag `--owner` dan `--same-unit` menyatakan relasi benar. Jika flag tidak diberikan, nilainya salah.

| Kode keluar | Arti |
| --- | --- |
| `0` | Validasi atau penjelasan selesai. Audit lolos atau diff menemukan nol izin baru. `explain` tetap selesai dengan kode ini ketika hasil simulasinya `deny`. |
| `1` | Audit menemukan pelanggaran atau pemeriksaan tanpa cakupan. Pada diff, ada skenario yang berubah menjadi `allow`. |
| `2` | Argumen, berkas, atau model kebijakan tidak valid untuk operasi tersebut. |

## Format kebijakan

Kebijakan dan hasil JSON bisa disimpan bersama source aplikasi. Dua kebijakan lengkap tersedia di direktori `examples/`. Berikut contoh minimal dengan satu aturan dan satu pemeriksaan.

```json
{
  "version": 1,
  "roles": { "wali": [] },
  "resources": { "dokumen": ["baca"] },
  "rules": [
    {
      "id": "wali-baca-milik",
      "effect": "allow",
      "roles": ["wali"],
      "resource": "dokumen",
      "actions": ["baca"],
      "when": { "owner": true }
    }
  ],
  "checks": [
    {
      "id": "wali-tolak-dokumen-lain",
      "expect": "deny",
      "resource": "dokumen",
      "actions": ["baca"],
      "subject": { "allRoles": ["wali"] },
      "when": { "owner": false }
    }
  ]
}
```

| Bagian | Cara dibaca |
| --- | --- |
| `roles` | Nama role dipetakan ke daftar role induk. `"koordinator": ["asisten"]` membuat koordinator mewarisi izin dan penolakan yang cocok untuk asisten. |
| `resources` | Nama resource dipetakan ke daftar aksi yang dikenali. |
| `rules` | Aturan cocok jika salah satu role yang disebutkan ada pada role efektif dan semua relasi pada `when` terpenuhi. `["*"]` cocok untuk semua subjek, termasuk anonim. |
| `when` | Objek opsional berisi `owner` dan/atau `sameUnit` bernilai boolean. Relasi yang tidak dicantumkan bebas bernilai benar atau salah. |
| `checks` | Ekspektasi `allow` atau `deny` untuk aksi tertentu. `audit` membutuhkan sedikitnya satu pemeriksaan. |
| `checks[].subject` | Filter opsional terhadap role yang diberikan secara langsung. `allRoles` mewajibkan semua role yang disebut, `noRoles` mengecualikan subjek yang memiliki salah satunya, dan `anonymous` memfilter status anonim. Jika kosong, semua subjek masuk cakupan. |

Nama role, resource, aksi, dan ID memakai 1–32 karakter huruf kecil ASCII, angka, garis bawah, atau tanda hubung, diawali huruf. ID aturan dan ID pemeriksaan masing-masing harus unik di bagiannya.

## Keputusan teknis dan jaminan

- **Aturan keputusan.** Akses hanya diizinkan jika ada aturan `allow` yang cocok dan tidak ada aturan `deny` yang cocok. Urutan deklarasi tidak memengaruhi keputusan.
- **Cakupan terukur.** Untuk setiap pasangan resource dan aksi, ada satu skenario anonim dan empat kombinasi `owner` serta `sameUnit` per himpunan role yang tidak kosong. `audit` menerapkan setiap pemeriksaan ke seluruh skenario yang cocok dan menandai pemeriksaan tanpa skenario sebagai gagal. `diff` menelusuri seluruh ruang model untuk katalog yang sama. Pewarisan role dapat berbeda antara versi.
- **Hasil deterministik.** Nama, aturan, dan pemeriksaan diurutkan sebelum evaluasi. Himpunan role terkecil diperiksa lebih dulu. Urutan deklarasi dapat diubah tanpa mengubah byte laporan JSON selama isi dan opsi tetap sama. Batas jumlah contoh tidak mengubah cakupan audit.

| Berkas | Tanggung jawab |
| --- | --- |
| `src/policy.js` | Membaca JSON, memvalidasi skema, menutup graf pewarisan dengan bitmask, dan mengevaluasi aturan. |
| `src/audit.js` | Menelusuri ruang skenario dan mengumpulkan hasil audit serta diff. |
| `src/cli.js` | Menangani argumen, laporan terminal dan JSON, serta kode keluar. |
| `test/cli.test.js` | Menguji alur CLI, aturan konflik, cakupan, kasus gagal, dan determinisme. |

Model menggunakan kombinasi role yang dideklarasikan dan dua relasi boolean. Ia mengasumsikan keempat kombinasi relasi mungkin untuk subjek yang memiliki role, dan hanya `owner=false` serta `sameUnit=false` untuk anonim. Aturan tentang kombinasi role yang mustahil dan identitas pengguna aktual berada di luar model. Hasil audit berlaku untuk kebijakan simulasi, sementara implementasi middleware perlu diuji di aplikasinya.

Input kebijakan dibatasi 256 KiB per berkas, maksimal 10 role, 12 resource, 48 pasangan resource/aksi, 128 aturan, dan 48 pemeriksaan. CLI bekerja lokal dan membuka kebijakan dalam mode baca-saja.

Prinsip penolakan bawaan dapat dibaca di [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html#deny-by-default).

## Tes

```powershell
node --test
```

Tes integrasi mencakup audit aman dan longgar, konflik izin dan penolakan, pewarisan transitif, semua 4.093 skenario untuk sepuluh role dan satu aksi, kegagalan karena cakupan kosong, validasi JSON, dan laporan yang identik saat urutan deklarasi dibalik.
