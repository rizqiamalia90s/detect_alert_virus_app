class VirusDatabase:
    def __init__(self):
        self.signatures = [
            {
                'nama_file': 'python.exe',  # Untuk fake_virus.py
                'signature': b'Program simulasi berjalan',
                'ukuran': 1024,
                'level_bahaya': 'Rendah',
                'deskripsi': 'File simulasi untuk pembelajaran',
                'tanggal_ditemukan': '2023-10-20'
            },
            {
                'nama_file': 'fake_virus',  # Untuk fake_virus.py
                'signature': b'Program simulasi berjalan',
                'ukuran': 1024,
                'level_bahaya': 'Rendah',
                'deskripsi': 'File simulasi virus untuk pembelajaran',
                'tanggal_ditemukan': '2023-10-20'
            },
            {
                'nama_file': 'fake_virus2',  # Untuk fake_virus2.py
                'signature': b'Program simulasi kedua',
                'ukuran': 1024,
                'level_bahaya': 'Sedang',
                'deskripsi': 'File simulasi virus kedua untuk testing multiple detection',
                'tanggal_ditemukan': '2023-10-20'
            }
        ]

    def cari_virus(self, nama_file):
        nama_file = nama_file.lower()
        return [v for v in self.signatures if 
                v['nama_file'].lower() in nama_file or 
                nama_file in v['nama_file'].lower()]