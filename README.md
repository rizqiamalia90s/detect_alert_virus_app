# detect_alert_virus_app
Kode Program untuk mendeteksi adanya file yang dianggap mencurigakan dan juga memunculkan baris alert file berbahaya serta dependensi lainnya yang dibutuhkan untuk menjadi sebuah aplikasi deteksi sederhana. Terdapat file aplikasi (allinone.py), 2 file virus buatan (fake_virus.py dan fake_virus2.py), serta database virus (virus_database.py).

Cara kerja sederhana : 
1. sistem akan berjalan sesuai dengan perintah user dilengkapi dengan fitur scanner yang akan memindai semua proses yang berjalan di task manager
2. selanjutnya sistem akan memberikan keterangan aman/mencurigakan suatu proses setelah sistem melakukan compare (perbandingan) atribut proses yang sedang berjalan dengan yang ada di database virus
3. jika persis/mendekati maka sistem akan menetapkan sebagai "file mencurigakan ditemukan" berdasarkan data yang ada di basis data.

(masih belum lengkap, tunggu update ya >_<)
