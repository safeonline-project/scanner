import ipaddress
import requests
import sys
import socket
import os

# Конфигурация
DISCORD_WEBHOOK_URL = ""
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""

# Флаги доступности сервисов
HAS_DISCORD = bool(DISCORD_WEBHOOK_URL.strip())
HAS_TELEGRAM = bool(TELEGRAM_BOT_TOKEN.strip()) and bool(TELEGRAM_CHAT_ID.strip())

# Проверка, открыт ли порт
def check_port(ip, port=80, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        return result == 0  # Порт открыт, если результат 0
    except socket.error:
        return False

# Загружаем подсети из ip.txt
def load_subnets(filename="ip.txt"):
    subnets = []
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        subnets.append(ipaddress.ip_network(line))
                    except ValueError:
                        print(f"[!] Некорректная подсеть: {line}")
    except FileNotFoundError:
        print(f"[!] Файл {filename} не найден")
    return subnets

# Загружаем URI из uri.txt
def load_uris(filename="uri.txt"):
    uris = []
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip().lstrip("/")
                if line and not line.startswith("#"):
                    uris.append(line)
    except FileNotFoundError:
        print(f"[!] Файл {filename} не найден")
    return uris

# Проверка URL -> возвращает (is_suspicious, status_code)
def check_url(url):
    try:
        r = requests.get(
            url,
            timeout=5,
            stream=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Antibotnet/0.1"}
        )
        code = r.status_code
        if code not in (200, 206):
            return False, code

        content_type = r.headers.get("Content-Type", "").lower()

        # отбрасываем текстовые/обычные страницы
        bad_types = ["text/html", "text/plain", "image/", "json", "xml"]
        if any(bt in content_type for bt in bad_types):
            return False, code

        # читаем первые байты
        chunk = next(r.iter_content(512), b"")

        # если HTML
        if b"<html" in chunk.lower():
            return False, code

        # ELF бинарь
        if chunk.startswith(b"\x7fELF"):
            return True, code

        # Скрипты
        if chunk.startswith(b"#!/bin/sh") or chunk.startswith(b"#!/bin/bash"):
            return True, code

        # По расширению URI
        for ext in (".sh", ".bin", ".elf", ".exe", ".php", ".cgi"):
            if url.lower().endswith(ext):
                return True, code

        # Если тип бинарный
        if "application/octet-stream" in content_type or "binary" in content_type:
            return True, code

        return False, code
    except requests.RequestException:
        return False, None

# Отправка в Discord (только если есть webhook)
def send_discord(message):
    if not HAS_DISCORD:
        return  # Не тратим время, если нет webhook
    
    try:
        payload = {"content": message}
        r = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        if r.status_code not in (200, 204):
            print(f"[!] Ошибка отправки в Discord: {r.status_code} {r.text}")
    except Exception as e:
        print(f"[!] Discord webhook ошибка: {e}")

# Отправка в Telegram (только если есть токен и chat ID)
def send_telegram(message):
    if not HAS_TELEGRAM:
        return  # Не тратим время, если нет токена или chat ID
    
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }
        r = requests.post(url, json=payload, timeout=5)
        if r.status_code != 200:
            print(f"[!] Ошибка отправки в Telegram: {r.status_code} {r.text}")
    except Exception as e:
        print(f"[!] Telegram ошибка: {e}")

# Запись только в файлы (используется всегда)
def write_to_files(url, status_code, detected=False):
    mode = "a"  # append mode
    
    # Всегда пишем в log.txt
    with open("log.txt", mode, encoding="utf-8") as f_log:
        f_log.write(f"{url} - {status_code if status_code else 'ERR'}\n")
    
    # Пишем в detect.txt если обнаружено
    if detected:
        with open("detect.txt", mode, encoding="utf-8") as f_detect:
            f_detect.write(f"{url} - {status_code}\n")

def main():
    # Выводим информацию о конфигурации
    print("[CONFIG] Проверка настроек:")
    print(f"  Discord Webhook: {'ЕСТЬ' if HAS_DISCORD else 'НЕТ'}")
    print(f"  Telegram Bot: {'ЕСТЬ' if HAS_TELEGRAM else 'НЕТ'}")
    print(f"  Telegram Chat ID: {'ЕСТЬ' if TELEGRAM_CHAT_ID.strip() else 'НЕТ'}")
    
    # Проверяем наличие необходимых файлов
    if not os.path.exists("ip.txt"):
        print("[!] Файл ip.txt не найден!")
        return
        
    if not os.path.exists("uri.txt"):
        print("[!] Файл uri.txt не найден!")
        return
    
    subnets = load_subnets("ip.txt")
    uris = load_uris("uri.txt")

    if not subnets:
        print("[!] Нет подсетей для сканирования")
        return
        
    if not uris:
        print("[!] Нет URI для проверки")
        return

    print(f"[+] Загружено {len(uris)} URI из uri.txt")
    print(f"[+] Загружено {len(subnets)} подсетей из ip.txt")

    total = sum(len(list(net.hosts())) for net in subnets) * len(uris)
    current = 0
    detected = 0

    # Очищаем файлы перед началом сканирования
    open("detect.txt", "w").close()
    open("log.txt", "w").close()

    print(f"\n[+] Начинаем сканирование ({total} URL)...")

    for net in subnets:
        for ip in net.hosts():
            # Проверяем порт 80 перед сканированием
            if not check_port(ip):
                for uri in uris:
                    current += 1
                    url = f"http://{ip}/{uri}"
                    sys.stdout.write(f"\r[SCAN] {current}/{total} -> {url} - PORT CLOSED")
                    sys.stdout.flush()
                    write_to_files(url, "PORT CLOSED", False)
                continue  # Пропускаем IP, если порт закрыт

            for uri in uris:
                current += 1
                url = f"http://{ip}/{uri}"

                ok, code = check_url(url)

                # прогресс
                sys.stdout.write(f"\r[SCAN] {current}/{total} -> {url} - {code if code else 'ERR'}")
                sys.stdout.flush()

                if ok:  # подозрительный ресурс
                    print(f"\n[DETECT] {url} - {code}")
                    write_to_files(url, code, True)
                    
                    # Отправляем уведомления только если есть конфигурация
                    send_discord(f"{url} - {code}")
                    send_telegram(f"<b>DETECT:</b>\n{url}\nStatus: {code}")
                    
                    detected += 1
                else:
                    write_to_files(url, code if code else 'ERR', False)

    print(f"\n[+] Сканирование завершено. Найдено: {detected}")
    
    # Итоговый отчет
    if detected > 0:
        final_msg = f"Сканирование завершено. Найдено подозрительных ресурсов: {detected}"
        send_discord(final_msg)
        send_telegram(f"<b>Сканирование завершено</b>\nНайдено: {detected}")

if __name__ == "__main__":
    main()import ipaddress
import requests
import sys
import socket
import os

# Конфигурация
DISCORD_WEBHOOK_URL = ""
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""

# Флаги доступности сервисов
HAS_DISCORD = bool(DISCORD_WEBHOOK_URL.strip())
HAS_TELEGRAM = bool(TELEGRAM_BOT_TOKEN.strip()) and bool(TELEGRAM_CHAT_ID.strip())

# Проверка, открыт ли порт
def check_port(ip, port=80, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        return result == 0  # Порт открыт, если результат 0
    except socket.error:
        return False

# Загружаем подсети из ip.txt
def load_subnets(filename="ip.txt"):
    subnets = []
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        subnets.append(ipaddress.ip_network(line))
                    except ValueError:
                        print(f"[!] Некорректная подсеть: {line}")
    except FileNotFoundError:
        print(f"[!] Файл {filename} не найден")
    return subnets

# Загружаем URI из uri.txt
def load_uris(filename="uri.txt"):
    uris = []
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip().lstrip("/")
                if line and not line.startswith("#"):
                    uris.append(line)
    except FileNotFoundError:
        print(f"[!] Файл {filename} не найден")
    return uris

# Проверка URL -> возвращает (is_suspicious, status_code)
def check_url(url):
    try:
        r = requests.get(
            url,
            timeout=5,
            stream=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Antibotnet/0.1"}
        )
        code = r.status_code
        if code not in (200, 206):
            return False, code

        content_type = r.headers.get("Content-Type", "").lower()

        # отбрасываем текстовые/обычные страницы
        bad_types = ["text/html", "text/plain", "image/", "json", "xml"]
        if any(bt in content_type for bt in bad_types):
            return False, code

        # читаем первые байты
        chunk = next(r.iter_content(512), b"")

        # если HTML
        if b"<html" in chunk.lower():
            return False, code

        # ELF бинарь
        if chunk.startswith(b"\x7fELF"):
            return True, code

        # Скрипты
        if chunk.startswith(b"#!/bin/sh") or chunk.startswith(b"#!/bin/bash"):
            return True, code

        # По расширению URI
        for ext in (".sh", ".bin", ".elf", ".exe", ".php", ".cgi"):
            if url.lower().endswith(ext):
                return True, code

        # Если тип бинарный
        if "application/octet-stream" in content_type or "binary" in content_type:
            return True, code

        return False, code
    except requests.RequestException:
        return False, None

# Отправка в Discord (только если есть webhook)
def send_discord(message):
    if not HAS_DISCORD:
        return  # Не тратим время, если нет webhook
    
    try:
        payload = {"content": message}
        r = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        if r.status_code not in (200, 204):
            print(f"[!] Ошибка отправки в Discord: {r.status_code} {r.text}")
    except Exception as e:
        print(f"[!] Discord webhook ошибка: {e}")

# Отправка в Telegram (только если есть токен и chat ID)
def send_telegram(message):
    if not HAS_TELEGRAM:
        return  # Не тратим время, если нет токена или chat ID
    
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }
        r = requests.post(url, json=payload, timeout=5)
        if r.status_code != 200:
            print(f"[!] Ошибка отправки в Telegram: {r.status_code} {r.text}")
    except Exception as e:
        print(f"[!] Telegram ошибка: {e}")

# Запись только в файлы (используется всегда)
def write_to_files(url, status_code, detected=False):
    mode = "a"  # append mode
    
    # Всегда пишем в log.txt
    with open("log.txt", mode, encoding="utf-8") as f_log:
        f_log.write(f"{url} - {status_code if status_code else 'ERR'}\n")
    
    # Пишем в detect.txt если обнаружено
    if detected:
        with open("detect.txt", mode, encoding="utf-8") as f_detect:
            f_detect.write(f"{url} - {status_code}\n")

def main():
    # Выводим информацию о конфигурации
    print("[CONFIG] Проверка настроек:")
    print(f"  Discord Webhook: {'ЕСТЬ' if HAS_DISCORD else 'НЕТ'}")
    print(f"  Telegram Bot: {'ЕСТЬ' if HAS_TELEGRAM else 'НЕТ'}")
    print(f"  Telegram Chat ID: {'ЕСТЬ' if TELEGRAM_CHAT_ID.strip() else 'НЕТ'}")
    
    # Проверяем наличие необходимых файлов
    if not os.path.exists("ip.txt"):
        print("[!] Файл ip.txt не найден!")
        return
        
    if not os.path.exists("uri.txt"):
        print("[!] Файл uri.txt не найден!")
        return
    
    subnets = load_subnets("ip.txt")
    uris = load_uris("uri.txt")

    if not subnets:
        print("[!] Нет подсетей для сканирования")
        return
        
    if not uris:
        print("[!] Нет URI для проверки")
        return

    print(f"[+] Загружено {len(uris)} URI из uri.txt")
    print(f"[+] Загружено {len(subnets)} подсетей из ip.txt")

    total = sum(len(list(net.hosts())) for net in subnets) * len(uris)
    current = 0
    detected = 0

    # Очищаем файлы перед началом сканирования
    open("detect.txt", "w").close()
    open("log.txt", "w").close()

    print(f"\n[+] Начинаем сканирование ({total} URL)...")

    for net in subnets:
        for ip in net.hosts():
            # Проверяем порт 80 перед сканированием
            if not check_port(ip):
                for uri in uris:
                    current += 1
                    url = f"http://{ip}/{uri}"
                    sys.stdout.write(f"\r[SCAN] {current}/{total} -> {url} - PORT CLOSED")
                    sys.stdout.flush()
                    write_to_files(url, "PORT CLOSED", False)
                continue  # Пропускаем IP, если порт закрыт

            for uri in uris:
                current += 1
                url = f"http://{ip}/{uri}"

                ok, code = check_url(url)

                # прогресс
                sys.stdout.write(f"\r[SCAN] {current}/{total} -> {url} - {code if code else 'ERR'}")
                sys.stdout.flush()

                if ok:  # подозрительный ресурс
                    print(f"\n[DETECT] {url} - {code}")
                    write_to_files(url, code, True)
                    
                    # Отправляем уведомления только если есть конфигурация
                    send_discord(f"{url} - {code}")
                    send_telegram(f"<b>DETECT:</b>\n{url}\nStatus: {code}")
                    
                    detected += 1
                else:
                    write_to_files(url, code if code else 'ERR', False)

    print(f"\n[+] Сканирование завершено. Найдено: {detected}")
    
    # Итоговый отчет
    if detected > 0:
        final_msg = f"Сканирование завершено. Найдено подозрительных ресурсов: {detected}"
        send_discord(final_msg)
        send_telegram(f"<b>Сканирование завершено</b>\nНайдено: {detected}")

if __name__ == "__main__":
    main()
