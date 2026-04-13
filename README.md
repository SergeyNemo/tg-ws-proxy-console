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
    "4:149.154.167.92",
    "203:149.154.167.220"
  ],
  "cfproxy_enabled": false,
  "cfproxy_priority": false,
  "cfproxy_auto_refresh": false,
  "cfproxy_domains": [],
  "buf_kb": 256,
  "pool_size": 4,
  "verbose": false
}
```

## Если В Группах Не Грузятся Медиа

По умолчанию CF-режим выключен.  
Если фото/видео в группах не открываются, включите CF fallback:

```json
"cfproxy_enabled": true,
"cfproxy_priority": true,
"cfproxy_auto_refresh": true,
"cfproxy_domains": []
```

Если позже появится свой домен, лучше использовать его:

```json
"cfproxy_enabled": true,
"cfproxy_priority": true,
"cfproxy_auto_refresh": false,
"cfproxy_domains": ["your-domain.com"]
```

Настройки можно посмотреть у автора в файле: https://github.com/Flowseal/tg-ws-proxy/blob/main/docs/CfProxy.md

## Главное по параметрам

- `host`: для безопасного локального режима оставляйте `127.0.0.1`.
- `dc_ip`: рабочие DC-адреса для проксирования Telegram.
- `cfproxy_enabled`: включает fallback через Cloudflare-домены.
- `cfproxy_priority`: если `true`, сначала пробуется CF, потом обычный путь.
- `cfproxy_domains`: если заполнен, используются только эти домены.
- `cfproxy_auto_refresh`: автообновление CF-списка (когда `cfproxy_domains` пуст).
- `buf_kb`, `pool_size`: параметры производительности.

## Что улучшено по безопасности (относительно оригинала)

- Включена строгая проверка TLS-сертификатов.
- Ограничен максимальный размер WS-фрейма (защита от перегрузки памяти).
- Из debug-логов убраны чувствительные криптоданные.
- Есть ограничение числа одновременных подключений.
- Есть предупреждение при небезопасном `host` (например, `0.0.0.0`).

## Важно

- Проект основан на [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) (MIT).
