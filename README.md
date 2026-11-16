# TG WS Proxy (Console)

Локальный SOCKS5-прокси для Telegram Desktop.  
Нужен, чтобы Telegram работал стабильнее в сетях с ограничениями.

## Быстрый старт

1. Установите зависимости:
```bash
pip install -r requirements.txt
```

2. Создайте `config/config.json` (можно взять `config/config.example.json`).

3. Запустите:
```bash
python windows.py
```

## Пример простого конфига

```json
{
  "port": 1080,
  "host": "127.0.0.1",
  "username": "username",
  "password": "your_password_here",
  "dc_ip": [
    "2:149.154.167.220",
    "4:149.154.167.220",
    "203:149.154.167.220"
  ],
  "cfproxy_enabled": true,
  "cfproxy_priority": true,
  "cfproxy_auto_refresh": true,
  "cfproxy_domains": [],
  "cfproxy_sni": "auto",
  "buf_kb": 256,
  "pool_size": 4,
  "verbose": false
}
```

## Если В Группах Не Грузятся Медиа

CF-режим в примере уже включён.  
Если медиа всё равно не грузится, попробуйте:

```json
"cfproxy_priority": true,
"cfproxy_sni": "apex"
```

Если позже появится свой домен, лучше использовать его:

```json
"cfproxy_enabled": true,
"cfproxy_priority": true,
"cfproxy_auto_refresh": false,
"cfproxy_domains": ["your-domain.com"]
```

## Главное по параметрам

- `host`: для безопасного локального режима оставляйте `127.0.0.1`.
- `dc_ip`: рабочие DC-адреса для проксирования Telegram. Если указан один IP, DC 1-5 и 203 добавляются автоматически.
- `cfproxy_enabled`: включает fallback через Cloudflare-домены.
- `cfproxy_priority`: если `true`, сначала пробуется CF, потом обычный путь.
- `cfproxy_domains`: если заполнен, используются только эти домены.
- `cfproxy_auto_refresh`: автообновление CF-списка (когда `cfproxy_domains` пуст).
- `cfproxy_sni`: `auto` (по умолчанию) — для CF сначала пробуется SNI домена, потом apex; `apex` — всегда apex (обход фильтрации по SNI, TLS-проверка остаётся включённой); `sub` — всегда домен.
- `buf_kb`, `pool_size`: параметры производительности.

## Что улучшено по безопасности (относительно оригинала)

- Включена строгая проверка TLS-сертификатов.
- Ограничен максимальный размер WS-фрейма (защита от перегрузки памяти).
- Из debug-логов убраны чувствительные криптоданные.
- Есть ограничение числа одновременных подключений.
- Есть предупреждение при небезопасном `host` (например, `0.0.0.0`).
- Домены в логах маскируются.

## Взято из оригинала (Flowseal)

- Список CF-доменов с GitHub и его валидация (проверка формата, порог минимума).
- Загрузка списка по HTTPS с закреплёнными IP GitHub.
- Проверка сертификатов через certifi + кривая X25519 (меньше ClientHello, реже срабатывает DPI).
- Экспоненциальный backoff при переподключении WS-пула и TCP fallback.
- Защита от потери wakeup-сокета event loop на Windows (`proxy/event_loop.py`).
- Маскирование доменов в логах.
- CF-подключения только к `kws{N}.<домен>` (варианта `kws{N}-1` не существует).

## Важно

- Проект основан на [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) (MIT).
- Не перенесено: HTTP/2-медиа, Fake TLS, GUI и автообновление.
