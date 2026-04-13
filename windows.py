"""
windows.py  —  Console Edition (Secure Version)
==================================================
Консольное приложение для запуска TG WS Proxy.

Загружает конфиг из config/config.json и запускает SOCKS5 прокси
с поддержкой аутентификации (username/password).
"""
from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
import signal
import sys
from pathlib import Path
from typing import Optional, Dict, Any

import proxy.tg_ws_proxy as tg_ws_proxy


# ============================================================================
# Paths & Constants
# ============================================================================

# Определяем папку приложения (работает как для Python, так и для EXE)
if getattr(sys, 'frozen', False):
    # Запуск из EXE (PyInstaller) — ищем конфиг в папке выше dist/
    APP_DIR = Path(sys.executable).parent.parent
else:
    # Запуск напрямую из Python
    APP_DIR = Path(__file__).parent

CONFIG_DIR = APP_DIR / "config"
LOGS_DIR = APP_DIR / "logs"
CONFIG_FILE = CONFIG_DIR / "config.json"
LOG_FILE = LOGS_DIR / "proxy.log"

DEFAULT_CONFIG = {
    "port": 1080,
    "host": "127.0.0.1",
    "username": "telegram",
    "password": "your_password_here",
    "dc_ip": [
        "2:149.154.167.220",
        "4:149.154.167.92",
        "203:149.154.167.220"
    ],
    "cfproxy_enabled": False,
    "cfproxy_priority": False,
    "cfproxy_auto_refresh": True,
    "cfproxy_domains": [],
    "buf_kb": 256,
    "pool_size": 4,
    "verbose": False,
}

# ============================================================================
# Logging Setup
# ============================================================================

def setup_logging(verbose: bool = False) -> None:
    """Настройка логирования в консоль и файл."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    
    log_format = logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Корневой логгер
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Консоль
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_format)
    root_logger.addHandler(console_handler)
    
    # Файл (rotating)
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10 МБ
        backupCount=3
    )
    file_handler.setFormatter(log_format)
    root_logger.addHandler(file_handler)


# ============================================================================
# Config Management
# ============================================================================

def load_config() -> Dict[str, Any]:
    """Загружает конфиг из config/config.json."""
    if not CONFIG_FILE.exists():
        log = logging.getLogger("tg-ws-console")
        log.error(f"Config file not found: {CONFIG_FILE}")
        log.error(f"Please create {CONFIG_FILE} with the following template:")
        print(json.dumps(DEFAULT_CONFIG, indent=2))
        sys.exit(1)
    
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Валидация обязательных полей
        required_keys = {"port", "host", "username", "password"}
        missing = required_keys - set(config.keys())
        if missing:
            log = logging.getLogger("tg-ws-console")
            log.error(f"Missing required config keys in {CONFIG_FILE}: {missing}")
            sys.exit(1)
        
        return config
    except json.JSONDecodeError as e:
        log = logging.getLogger("tg-ws-console")
        log.error(f"Invalid JSON in config: {e}")
        sys.exit(1)
    except Exception as e:
        log = logging.getLogger("tg-ws-console")
        log.error(f"Error loading config: {e}")
        sys.exit(1)


# ============================================================================
# Proxy Server
# ============================================================================

async def run_proxy(config: Dict[str, Any]) -> None:
    """Запускает SOCKS5 прокси-сервер с аутентификацией."""
    log = logging.getLogger("tg-ws-console")
    
    port = config.get("port", 1080)
    host = config.get("host", "127.0.0.1")
    username = config.get("username", "telegram")
    password = config.get("password", "")
    dc_ip = config.get("dc_ip", [])
    cfproxy_enabled = bool(config.get("cfproxy_enabled", False))
    cfproxy_priority = bool(config.get("cfproxy_priority", False))
    cfproxy_auto_refresh = bool(config.get("cfproxy_auto_refresh", True))
    cfproxy_domains = config.get("cfproxy_domains", [])
    buf_kb = config.get("buf_kb", 256)
    pool_size = config.get("pool_size", 4)
    verbose = config.get("verbose", False)

    if not isinstance(dc_ip, list):
        log.error("Invalid config: 'dc_ip' must be a list")
        sys.exit(1)
    if not isinstance(cfproxy_domains, list):
        log.error("Invalid config: 'cfproxy_domains' must be a list")
        sys.exit(1)
    if not isinstance(buf_kb, int):
        log.error("Invalid config: 'buf_kb' must be an integer")
        sys.exit(1)
    if not isinstance(pool_size, int):
        log.error("Invalid config: 'pool_size' must be an integer")
        sys.exit(1)
    cfproxy_domains = [d.strip().lower() for d in cfproxy_domains
                       if isinstance(d, str) and d.strip()]
    
    # Передаём аутентификацию в tg_ws_proxy через глобальные переменные
    tg_ws_proxy.SOCKS5_USERNAME = username
    tg_ws_proxy.SOCKS5_PASSWORD = password
    tg_ws_proxy.SOCKS5_AUTH_ENABLED = bool(password)
    tg_ws_proxy.CFPROXY_ENABLED = bool(cfproxy_enabled)
    tg_ws_proxy.CFPROXY_PRIORITY = bool(cfproxy_priority)
    tg_ws_proxy.CFPROXY_DOMAINS = cfproxy_domains
    tg_ws_proxy.CFPROXY_CUSTOM_DOMAINS = bool(cfproxy_domains)
    tg_ws_proxy.CFPROXY_AUTO_REFRESH = bool(cfproxy_auto_refresh)
    tg_ws_proxy.SOCKET_BUFFER_SIZE = max(4, int(buf_kb)) * 1024
    tg_ws_proxy.WS_POOL_SIZE = max(0, int(pool_size))
    
    # Распарсим список DC-адресов
    try:
        dc_opt = tg_ws_proxy.parse_dc_ip_list(dc_ip)
    except ValueError as e:
        log.error(f"Invalid DC IP list: {e}")
        sys.exit(1)
    
    # Запускаем основной сервер
    try:
        log.info(f"Starting TG WS Proxy on {host}:{port}")
        if username and password != DEFAULT_CONFIG.get("password"):
            log.info(f"Authentication enabled (username: {username})")
        else:
            log.warning("[!] Using default password - please change in config/config.json")
        
        if dc_ip:
            log.info(f"DC addresses: {len(dc_opt)} DataCenters configured")
        if tg_ws_proxy.CFPROXY_ENABLED:
            order = "CF-first" if tg_ws_proxy.CFPROXY_PRIORITY else "direct-first"
            mode = ("custom-domains" if tg_ws_proxy.CFPROXY_CUSTOM_DOMAINS
                    else ("auto-refresh" if tg_ws_proxy.CFPROXY_AUTO_REFRESH else "default-pool"))
            log.info(f"CF proxy enabled: {order}, mode={mode}")
        log.info(f"Performance: buf_kb={max(4, int(buf_kb))}, pool_size={max(0, int(pool_size))}")
        
        log.info(f"Verbose logging: {'ON' if verbose else 'OFF'}")
        log.info("Proxy is running. Press Ctrl+C to stop.\n")
        
        # Используем встроенную функцию запуска прокси
        await tg_ws_proxy._run(port, dc_opt, stop_event=None, host=host)
    
    except KeyboardInterrupt:
        log.info("\nShutting down...")
    except Exception as e:
        log.error(f"Fatal error: {e}", exc_info=verbose)
        sys.exit(1)


# ============================================================================
# Main Entry Point
# ============================================================================

def main() -> None:
    """Основная функция."""
    # Загружаем конфиг перед логированием, чтобы узнать verbose
    setup_logging(verbose=False)
    config = load_config()
    verbose = config.get("verbose", False)
    
    # Настраиваем логирование
    logging.getLogger().setLevel(logging.DEBUG if verbose else logging.INFO)
    
    log = logging.getLogger("tg-ws-console")
    log.info("=" * 70)
    log.info("TG WS Proxy — Console Edition (Secure)")
    log.info("=" * 70)
    log.info(f"Config loaded: {CONFIG_FILE}")
    
    # Обработчик сигналов
    def signal_handler(signum, frame):
        log.info("Signal received, shutting down...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Запускаем asyncio loop
    try:
        asyncio.run(run_proxy(config))
    except KeyboardInterrupt:
        pass
    finally:
        log.info("TG WS Proxy stopped.")


if __name__ == "__main__":
    main()
