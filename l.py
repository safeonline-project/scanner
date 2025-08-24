import ipaddress
import requests
import sys

WEBHOOK_URL = "https://discord.com/api/webhooks/1409216365868355614/ww3NcW3-MUp6L08QKdiL-HyeK1oRgoGr-Qq0hZ1tXxBrD36aFYh2sf5iJFoZSZVlW3ro"

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
            headers={"User-Agent": "Mozilla/5.0"}
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

# Отправка в Discord
def send_discord(message):
    try:
        payload = {"content": message}
        r = requests.post(WEBHOOK_URL, json=payload, timeout=5)
        if r.status_code != 204:
            print(f"[!] Ошибка отправки в Discord: {r.status_code} {r.text}")
    except Exception as e:
        print(f"[!] Discord webhook ошибка: {e}")

def main():
    subnets = load_subnets("ip.txt")
    uris = load_uris("uri.txt")

    print(f"[+] Загружено {len(uris)} URI из uri.txt")
    print(f"[+] Загружено {len(subnets)} подсетей из ip.txt")

    total = sum(len(list(net.hosts())) for net in subnets) * len(uris)
    current = 0
    detected = 0

    with open("detect.txt", "w") as f_detect, open("log.txt", "w") as f_log:
        for net in subnets:
            for ip in net.hosts():
                for uri in uris:
                    current += 1
                    url = f"http://{ip}/{uri}"

                    ok, code = check_url(url)

                    # прогресс
                    sys.stdout.write(f"\r[SCAN] {current}/{total} -> {url} - {code if code else 'ERR'}")
                    sys.stdout.flush()

                    if ok:  # подозрительный ресурс
                        print(f"\n[DETECT] {url} - {code}")
                        f_detect.write(f"{url} - {code}\n")
                        send_discord(f"{url} - {code}")
                        detected += 1
                    else:
                        f_log.write(f"{url} - {code if code else 'ERR'}\n")

    print(f"\n[+] Сканирование завершено. Найдено: {detected}")

if __name__ == "__main__":
    main()
