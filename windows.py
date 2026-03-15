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
        "1:149.154.175.50", "1:149.154.175.51", "1:149.154.175.54",
        "2:149.154.167.41", "2:149.154.167.50", "2:149.154.167.51", "2:149.154.167.220",
        "3:149.154.175.100", "3:149.154.175.101",
        "4:149.154.167.91", "4:149.154.167.92",
        "5:91.108.56.100", "5:91.108.56.101", "5:91.108.56.116", "5:91.108.56.126"
    ],
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
    verbose = config.get("verbose", False)
    
    # Передаём аутентификацию в tg_ws_proxy через глобальные переменные
    tg_ws_proxy.SOCKS5_USERNAME = username
    tg_ws_proxy.SOCKS5_PASSWORD = password
    tg_ws_proxy.SOCKS5_AUTH_ENABLED = bool(password)
    
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
