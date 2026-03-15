# TG WS Proxy — безопасная версия

SOCKS5-прокси для Telegram Desktop через WebSocket/TLS с исправленными уязвимостями безопасности.

**Авторство**

**Оригинальный проект:** [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) от [Flowseal](https://github.com/Flowseal) (MIT)  
**Форк & Исправления:** [Sergey Nemo](https://github.com/SergeyNemo) (2026)

Детали всех изменений в [CHANGES.md](./CHANGES.md).

---

## 🚀 Быстрый старт

### Требования

- Python 3.8+
- Windows / Linux / macOS

### Установка

```bash
git clone https://github.com/SergeyNemo/tg-ws-proxy-console
cd tg-ws-proxy-console
pip install -r requirements.txt

# Скопируйте пример конфига и заполните свои данные
cp config/config.example.json config/config.json
```

Отредактируйте `config/config.json` с вашими параметрами.

### Запуск (консольный режим)

```bash
python windows.py
```

### Запуск (прокси-сервер только)

```bash
python proxy/tg_ws_proxy.py --port 1080 -v
```

---

## ⚙️ Конфигурация

**Файл:** `config/config.json`

```json
{
  "port": 1080,
  "host": "127.0.0.1",
  "username": "telegram",
  "password": "your_strong_password_here",
  "dc_ip": [
    "1:149.154.175.50",
    "1:149.154.175.51",
    "1:149.154.175.54",
    "2:149.154.167.41",
    "2:149.154.167.50",
    "2:149.154.167.51",
    "2:149.154.167.151",
    "2:149.154.167.222",
    "2:149.154.167.220",
    "3:149.154.175.100",
    "3:149.154.175.101",
    "4:149.154.167.91",
    "4:149.154.164.250",
    "4:149.154.167.92",
    "5:91.108.56.100",
    "5:91.108.56.101",
    "5:91.108.56.103",
    "5:91.108.56.116",
    "5:91.108.56.126"
  ],
  "ipv6_mode": "auto",
  "ipv6_cooldown": 10,
  "verbose": false
}
```

**Параметры:**
- `port` — SOCKS5 порт (по умолчанию 1080)
- `host` — интерфейс слушания (`127.0.0.1` только локально)
- `username` / `password` — SOCKS5 аутентификация
- `dc_ip` — список Telegram DataCenter адресов
- `ipv6_mode` — режим IPv6: `auto` (отключает при ошибках), `on`, `off`
- `ipv6_cooldown` — время (сек) отключения IPv6 в режиме `auto`
- `verbose` — включить DEBUG логирование

**Примечание (DC203 / CDN):** Иногда в логах можно увидеть `unknown DC203 ... -> TCP passthrough`.  
Это означает, что соединение идёт на CDN‑адрес Telegram (например `91.105.192.100`), для которого WebSocket‑туннель не используется. В этом случае прокси автоматически делает прямой TCP fallback — это нормально.

---

## 📊 Логирование

**Файл:** `logs/proxy.log`

Автоматическая ротация:
- Размер: 10 МБ на файл
- Хранит: 3 последних файла
- Максимум: 40 МБ на диске

Пример:
```
2026-03-11 15:40:14 [INFO] stats: total=42 ws=15 tcp_fb=27 pass=0 err=0 up=15.3MB down=42.1MB
```

---

## 🛡️ Безопасность

**Для локального использования (рекомендуется):**
```json
{ "host": "127.0.0.1" }
```
- Доступен только с текущей машины
- Не требует дополнительной защиты

**Для сетевого доступа:**
- Используйте только в доверенной сети (LAN, VPN)
- Сильный пароль: 12+ символов, спецсимволы
- Firewall ограничение: `netsh advfirewall firewall add rule name="TG-SOCKS5" dir=in action=allow protocol=tcp localport=1080 remoteip=192.168.1.0/24`
- Защита файла: `icacls "config\config.json" /inheritance:r /grant:r "%USERNAME%:F"`

**Детально:** смотрите [CHANGES.md](./CHANGES.md)

---

## � Авторство

**Оригинальный проект:** [Flowseal](https://github.com/Flowseal/tg-ws-proxy) — MIT License

**Исправления безопасности:** [Sergey Nemo](https://github.com/SergeyNemo) (2026)

Детали изменений в [CHANGES.md](./CHANGES.md)

---

## 📄 Лицензия

MIT License — смотрите [LICENSE](./LICENSE) для полного текста.
