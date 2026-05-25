#!/usr/bin/env python3

import os
import subprocess
import re
import json

def get_user_auth():
    json_payload = json.dumps({

    "phone_number": "xxxxx",
    "password": "xxxxx"
    })

    command = [
        'curl', '-X','POST','https://xxxxxx/api/v1/auth/login-customer','-k','-H','Content-Type: application/json','-d',json_payload]
    proc = subprocess.run(command, capture_output=True, check=True, text=True)
    process_output = json.loads(proc.stdout.encode('utf-8'))
    return process_output['token']

def read_file(filepath):
    """Membaca file dan mengembalikan daftar URL di dalamnya."""
    if not os.path.isfile(filepath):
        print(f"Error: File '{filepath}' tidak ditemukan.")
        return []
        
    with open(filepath, 'r') as f:
        # Membaca tiap baris, menghapus spasi/newline, dan mengabaikan baris kosong
        return [line.strip() for line in f if line.strip()]

def sanitize_filename(url):
    """Mengubah karakter URL yang tidak valid menjadi underscore agar aman dijadikan nama file."""
    # Menghapus skema http:// atau https:// untuk nama file yang lebih bersih
    clean_url = re.sub(r'^https?://', '', url)
    return re.sub(r'[\\/*?:"<>|]', '_', clean_url) + "_contents.txt"

def call_url(urls, out_dir):
    """Memanggil tiap URL menggunakan curl dan menyimpan hasilnya ke out_dir."""
    # Membuat direktori jika belum ada
    os.makedirs(out_dir, exist_ok=True)
    token = get_user_auth()
    for url in urls:
        print(f"[*] Fetching: {url}")
        safe_filename = sanitize_filename(url)
        out_path = os.path.join(out_dir, safe_filename)
        
        # Menggunakan subprocess.run dengan curl. 
        # -k (insecure), -s (silent), -o (output ke file)
        # Menulis langsung via flag -o pada curl jauh lebih efisien daripada menangkap stdout
        try:
            subprocess.run(["curl","-b",f"token={token}", "-k", "-s", url, "-o", out_path], check=True)
            print(f"    [+] Disimpan di: {out_path}")
        except subprocess.CalledProcessError:
            print(f"    [-] Gagal melakukan curl pada: {url}")
            
    return "Pemanggilan URL Selesai!"

def start_yara_scan(rule_path, target_dir):
    """Menjalankan YARA scan pada direktori target menggunakan rule yang ditentukan."""
    if not os.path.isfile(rule_path):
        print(f"Error: YARA Rule '{rule_path}' tidak ditemukan.")
        return

    print(f"\n[*] Memulai YARA Scan menggunakan rule: {rule_path} pada direktori: {target_dir}")
    try:
        # Format perintah yara: yara [OPTIONS] RULES_FILE TARGET_DIR
        # -r = rekursif
        process = subprocess.run(["yara", "-rs", rule_path, target_dir], capture_output=True, text=True)
        
        if process.stdout:
            print("\n[+] Hasil Scan YARA:")
            print(process.stdout)
        elif process.returncode == 0:
            print("[-] Scan selesai, tidak ada temuan YARA yang cocok.")
        else:
            print(f"Error saat menjalankan YARA: {process.stderr}")
            
    except FileNotFoundError:
        print("Error: Command 'yara' tidak ditemukan. Pastikan YARA sudah terpasang di sistem.")

def main():
    url_file_path = input("Input URL File: ")
    yara_rule_path = input("Input YARA Rule: ")
    out_directory = input("Input Output Directory: ")
    
    urls = read_file(url_file_path)
    if not urls:
        print("Tidak ada URL yang dapat diproses. Program berhenti.")
        return

    print(call_url(urls, out_directory))
    start_yara_scan(yara_rule_path, out_directory)

if __name__ == "__main__":
    main()
