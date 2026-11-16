"""
tg_ws_proxy.py  —  Secure Edition
==================================
Локальный SOCKS5-прокси для Telegram Desktop.
Перенаправляет трафик Telegram-DC через WebSocket (TLS).

Исправления безопасности по сравнению с оригиналом:
  FIX-1  TLS-верификация включена (убраны check_hostname=False / CERT_NONE)
  FIX-2  Лимит размера WS-фрейма (MAX_WS_FRAME_SIZE) — защита от OOM
  FIX-3  Криптоматериал убран из debug-логов
  FIX-4  Периодическая очистка _dc_fail_until — нет утечки памяти
  FIX-5  Лимит одновременных подключений (_active_connections)
  FIX-6  Валидация аргумента --host
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import http.client
import logging
import os
import random
import re
import socket as _socket
import ssl
import string
import struct
import sys
import threading
import time
from collections import deque
from typing import Dict, List, Optional, Set, Tuple
from urllib.request import HTTPSHandler, Request, build_opener
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import certifi


DEFAULT_PORT      = 1080
DEFAULT_BUF_KB    = 256
DEFAULT_POOL_SIZE = 4
MAX_WS_FRAME_SIZE = 16 * 1024 * 1024   # FIX-2: 16 МБ — защита от OOM/DoS
MAX_CONNECTIONS   = 200                 # FIX-5: максимум одновременных соединений

log = logging.getLogger('tg-ws-proxy')

_TG_RANGES = [
    # 185.76.151.0/24
    (struct.unpack('!I', _socket.inet_aton('185.76.151.0'))[0],
     struct.unpack('!I', _socket.inet_aton('185.76.151.255'))[0]),
    # 149.154.160.0/20
    (struct.unpack('!I', _socket.inet_aton('149.154.160.0'))[0],
     struct.unpack('!I', _socket.inet_aton('149.154.175.255'))[0]),
    # 91.105.192.0/23
    (struct.unpack('!I', _socket.inet_aton('91.105.192.0'))[0],
     struct.unpack('!I', _socket.inet_aton('91.105.193.255'))[0]),
    # 91.108.0.0/16
    (struct.unpack('!I', _socket.inet_aton('91.108.0.0'))[0],
     struct.unpack('!I', _socket.inet_aton('91.108.255.255'))[0]),
]

# IP -> (dc_id, is_media)
_IP_TO_DC: Dict[str, Tuple[int, bool]] = {
    # DC1
    '149.154.175.50': (1, False), '149.154.175.51': (1, False),
    '149.154.175.53': (1, False), '149.154.175.54': (1, False),
    '149.154.175.52': (1, True),
    # DC2
    '149.154.167.41': (2, False), '149.154.167.50': (2, False),
    '149.154.167.51': (2, False), '149.154.167.220': (2, False),
    '95.161.76.100': (2, False),
    '149.154.167.151': (2, True), '149.154.167.222': (2, True),
    '149.154.167.223': (2, True), '149.154.162.123': (2, True),
    # DC3
    '149.154.175.100': (3, False), '149.154.175.101': (3, False),
    '149.154.175.102': (3, True),
    # DC4
    '149.154.167.91': (4, False), '149.154.167.92': (4, False),
    '149.154.164.250': (4, True), '149.154.166.120': (4, True),
    '149.154.166.121': (4, True), '149.154.167.118': (4, True),
    '149.154.165.111': (4, True),
    # DC5
    '91.108.56.100': (5, False), '91.108.56.101': (5, False),
    '91.108.56.116': (5, False), '91.108.56.126': (5, False),
    '149.154.171.5': (5, False),
    '91.108.56.102': (5, True), '91.108.56.128': (5, True),
    '91.108.56.151': (5, True),
    # DC203
    '91.105.192.100': (203, False),
}

_dc_opt: Dict[int, List[str]] = {}

# DCs where WS is known to fail (302 redirect) — TCP fallback will be used
_ws_blacklist: Set[Tuple[int, bool]] = set()

# Rate-limit re-attempts per (dc, is_media)
_dc_fail_until: Dict[Tuple[int, bool], float] = {}
_DC_FAIL_COOLDOWN = 60.0  # seconds

# FIX-5: счётчик активных соединений (asyncio однопоточен — нет гонок)
_active_connections: int = 0

# SOCKS5 Authentication — глобальные переменные для логина и пароля
# Устанавливаются из windows.py при запуске
SOCKS5_USERNAME: str = ""
SOCKS5_PASSWORD: str = ""
# Признак включенной аутентификации (нужен для логов)
SOCKS5_AUTH_ENABLED: bool = False

# Optional CF-proxy fallback (configured from windows.py / CLI)
CFPROXY_ENABLED: bool = False
CFPROXY_PRIORITY: bool = False
CFPROXY_DOMAINS: List[str] = []
CFPROXY_CUSTOM_DOMAINS: bool = False
CFPROXY_AUTO_REFRESH: bool = True
CFPROXY_ACTIVE_DOMAIN: str = ""
# SNI для CF-пути: если DPI блокирует kwsN.<domain>, шлём apex-домен.
# 'sub' = всегда реальный SNI, 'apex' = всегда apex, 'auto' = SNI домена,
# затем apex-запас (по умолчанию).
CFPROXY_SNI_MODE: str = "auto"
CFPROXY_DOMAINS_URL = (
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main"
    "/.github/cfproxy-domains.txt"
)
_CFPROXY_ENC: List[str] = [
    'virkgj.com', 'vmmzovy.com', 'mkuosckvso.com', 'zaewayzmplad.com',
    'twdmbzcm.com'
]
_CF_SFX = ''.join(chr(c) for c in (46, 99, 111, 46, 117, 107))

# Performance settings (configured from windows.py / CLI)
SOCKET_BUFFER_SIZE: int = DEFAULT_BUF_KB * 1024
WS_POOL_SIZE: int = DEFAULT_POOL_SIZE

_cfproxy_refresh_stop: threading.Event = threading.Event()

# Per-host connect backoff: host -> monotonic deadline until which it is skipped
_host_cooldown_until: Dict[str, float] = {}
_host_fail_counts: Dict[str, int] = {}
HOST_COOLDOWN_INITIAL = 30.0
HOST_COOLDOWN_MAX = 600.0

# Сколько CF-хостов пробовать на один клиентский запрос (защита от лавины)
CF_MAX_ATTEMPTS_PER_REQUEST = 6

# DC, для которых direct-WS через kwsN.web.telegram.org невозможен:
# сервер на этом IP не отдаёт сертификат на это имя (hostname mismatch).
# Заполняется автоматически при первой такой ошибке, чтобы не спамить.
_dc_direct_unavailable: Set[int] = set()


def _dc_direct_disabled(dc: int) -> bool:
    return dc in _dc_direct_unavailable


def _mark_dc_direct_unavailable(dc: int, reason: str) -> None:
    if dc in _dc_direct_unavailable:
        return
    _dc_direct_unavailable.add(dc)
    log.info("DC%d: direct WS via kws%d.web.telegram.org unavailable (%s); "
             "routing through CF proxy only", dc, dc, reason)

# TCP fallback backoff: (dst, port) -> состояние
_tcp_connecting: Set[Tuple[str, int]] = set()
_tcp_failures: Dict[Tuple[str, int], int] = {}
_tcp_retry_after: Dict[Tuple[str, int], float] = {}
TCP_BACKOFF_INITIAL = 2.0
TCP_BACKOFF_MAX = 300.0


def _create_ssl_context(*, check_hostname: bool = True) -> ssl.SSLContext:
    # FIX-1: TLS с полной верификацией — check_hostname=True, verify_mode=CERT_REQUIRED
    bundle_dir = getattr(sys, '_MEIPASS', None)
    cafile = (os.path.join(bundle_dir, 'certifi', 'cacert.pem')
              if bundle_dir else certifi.where())
    context = ssl.create_default_context(cafile=cafile)
    if bundle_dir:
        context.load_default_certs()
    # Понижаем приоритет X25519MLKEM768 (большой ClientHello триггерит DPI),
    # оставляя классический X25519 основным для TLS 1.3.
    try:
        context.set_ecdh_curve('X25519')
    except Exception:
        pass
    context.check_hostname = check_hostname
    return context


_ssl_ctx = _create_ssl_context()

_GITHUB_IPS: Dict[str, str] = {
    "release-assets.githubusercontent.com": "185.199.109.133",
    "raw.githubusercontent.com": "185.199.109.133",
}


class _PinnedHTTPSHandler(HTTPSHandler):
    def https_open(self, req):
        host = req.host.split(":")[0]
        pinned = _GITHUB_IPS.get(host)
        if not pinned:
            return super().https_open(req)
        context = _ssl_ctx

        class _Conn(http.client.HTTPSConnection):
            def connect(self):
                self.sock = _socket.create_connection(
                    (pinned, self.port or 443), self.timeout, self.source_address)
                if self._tunnel_host:
                    self._tunnel()
                self.sock = context.wrap_socket(
                    self.sock, server_hostname=self._tunnel_host or self.host)

        try:
            return self.do_open(_Conn, req, context=context)
        except Exception:
            return super().https_open(req)


def _build_github_opener():
    return build_opener(_PinnedHTTPSHandler())


class DomainCensorFilter(logging.Filter):
    domain_pattern = re.compile(
        r'(?<![\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,}(?![\w-])')

    def _censor_match(self, match):
        domain = match.group()
        normalized = domain.casefold().rstrip('.')
        if (normalized == 'telegram.org' or normalized.endswith('.telegram.org')
                or normalized.endswith('.log')):
            return domain
        parts = domain.split('.')
        if len(parts) < 2:
            return domain
        return '.'.join(
            part if i == len(parts) - 1 else
            part[:len(part) // 2] + '*' * (len(part) - len(part) // 2)
            for i, part in enumerate(parts))

    def filter(self, record):
        record.msg = self.domain_pattern.sub(self._censor_match, record.getMessage())
        record.args = ()
        return True



class WsHandshakeError(Exception):
    def __init__(self, status_code: int, status_line: str,
                 headers: dict = None, location: str = None):
        self.status_code = status_code
        self.status_line = status_line
        self.headers = headers or {}
        self.location = location
        super().__init__(f"HTTP {status_code}: {status_line}")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)


def _xor_mask(data: bytes, mask: bytes) -> bytes:
    if not data:
        return data
    a = bytearray(data)
    for i in range(len(a)):
        a[i] ^= mask[i & 3]
    return bytes(a)


def _decode_cf_domain(encoded: str) -> str:
    if not encoded.endswith('.com'):
        return encoded
    prefix = encoded[:-4]
    shift = sum(c.isalpha() for c in prefix)
    decoded = ''.join(
        chr((ord(c) - (97 if c > '`' else 65) - shift) % 26 +
            (97 if c > '`' else 65))
        if c.isalpha() else c
        for c in prefix
    )
    return decoded + _CF_SFX


CFPROXY_DEFAULT_DOMAINS: List[str] = [_decode_cf_domain(d) for d in _CFPROXY_ENC]

_CFPROXY_MIN_VALID_DOMAINS = 3


def _is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    if domain.startswith('.') or domain.endswith('.'):
        return False
    labels = domain.split('.')
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label[0] == '-' or label[-1] == '-':
            return False
        if not all(ch.isalnum() or ch == '-' for ch in label):
            return False
    tld = labels[-1]
    if len(tld) < 2 or not any(ch.isalpha() for ch in tld):
        return False
    return True


def _normalize_domain_pool(domains: List[str]) -> List[str]:
    seen: Set[str] = set()
    normalized: List[str] = []
    for domain in domains:
        item = domain.strip().lower()
        if not _is_valid_domain(item) or item in seen:
            continue
        seen.add(item)
        normalized.append(item)
    return normalized


def _fetch_cfproxy_domain_list() -> List[str]:
    try:
        suffix = "".join(random.choices(string.ascii_letters, k=7))
        req = Request(f"{CFPROXY_DOMAINS_URL}?{suffix}",
                      headers={'User-Agent': 'tg-ws-proxy'})
        with _build_github_opener().open(req, timeout=10) as resp:
            text = resp.read().decode('utf-8', errors='replace')
        encoded = [
            line.strip() for line in text.splitlines()
            if line.strip() and not line.startswith('#')
        ]
        return [_decode_cf_domain(d) for d in encoded]
    except Exception as exc:
        log.warning("Failed to fetch CF proxy domain list: %s", exc)
        return []


def refresh_cfproxy_domains() -> None:
    global CFPROXY_DOMAINS, CFPROXY_ACTIVE_DOMAIN
    fetched = _fetch_cfproxy_domain_list()
    pool = _normalize_domain_pool(fetched)

    if len(pool) >= _CFPROXY_MIN_VALID_DOMAINS:
        CFPROXY_DOMAINS = pool
        log.info("CF proxy domain pool updated from GitHub (%d domains)",
                 len(pool))
    elif fetched:
        log.warning(
            "Ignoring fetched CF proxy domains due to low-quality payload "
            "(total=%d, valid=%d, required>=%d); keeping current pool",
            len(fetched), len(pool), _CFPROXY_MIN_VALID_DOMAINS)
        if not CFPROXY_DOMAINS:
            CFPROXY_DOMAINS = list(CFPROXY_DEFAULT_DOMAINS)
    else:
        log.warning("CF proxy domain refresh failed or empty response; "
                    "keeping current pool")
        if not CFPROXY_DOMAINS:
            CFPROXY_DOMAINS = list(CFPROXY_DEFAULT_DOMAINS)

    if CFPROXY_DOMAINS and not CFPROXY_ACTIVE_DOMAIN:
        CFPROXY_ACTIVE_DOMAIN = random.choice(CFPROXY_DOMAINS)


def stop_cfproxy_domain_refresh() -> None:
    global _cfproxy_refresh_stop
    _cfproxy_refresh_stop.set()


def start_cfproxy_domain_refresh() -> None:
    global _cfproxy_refresh_stop
    _cfproxy_refresh_stop.set()
    _cfproxy_refresh_stop = threading.Event()
    stop = _cfproxy_refresh_stop

    def _loop():
        refresh_cfproxy_domains()
        while not stop.wait(timeout=3600):
            refresh_cfproxy_domains()

    threading.Thread(target=_loop, daemon=True,
                     name='cfproxy-domains-refresh').start()


def set_sock_opts(transport, buffer_size: int) -> None:
    sock = transport.get_extra_info('socket')
    if sock is None:
        return

    try:
        sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass

    try:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, buffer_size)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF, buffer_size)
    except OSError:
        pass


class RawWebSocket:
    """
    Lightweight WebSocket client over asyncio reader/writer streams.

    Connects directly to a target IP via TCP+TLS (bypassing any system
    proxy), performs the HTTP Upgrade handshake, and provides send/recv
    for binary frames with masking, ping/pong, and close handling.
    """

    OP_CONTINUATION = 0x0
    OP_TEXT         = 0x1
    OP_BINARY       = 0x2
    OP_CLOSE        = 0x8
    OP_PING         = 0x9
    OP_PONG         = 0xA

    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.reader   = reader
        self.writer   = writer
        self._closed  = False

    @staticmethod
    async def connect(ip: str, domain: str, path: str = '/apiws',
                      timeout: float = 10.0,
                      sni: Optional[str] = None) -> 'RawWebSocket':
        """
        Connect via TLS to ip:443, send SNI (defaults to domain),
        perform WebSocket upgrade, return RawWebSocket.
        Raises WsHandshakeError on non-101 response.
        """
        # FIX-1: TLS верифицирует цепочку и hostname SNI. Для CF-пути SNI может
        # отличаться от Host (apex-домен), проверка сертификата остаётся включённой.
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=_ssl_ctx,
                                    server_hostname=sni or domain),
            timeout=min(timeout, 10))

        set_sock_opts(writer.transport, SOCKET_BUFFER_SIZE)

        ws_key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {domain}\r\n'
            f'Upgrade: websocket\r\n'
            f'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Key: {ws_key}\r\n'
            f'Sec-WebSocket-Version: 13\r\n'
            f'Sec-WebSocket-Protocol: binary\r\n'
            f'Origin: https://web.telegram.org\r\n'
            f'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            f'AppleWebKit/537.36 (KHTML, like Gecko) '
            f'Chrome/131.0.0.0 Safari/537.36\r\n'
            f'\r\n'
        )
        writer.write(req.encode())
        await writer.drain()

        response_lines: list[str] = []
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(),
                                              timeout=timeout)
                if line in (b'\r\n', b'\n', b''):
                    break
                response_lines.append(
                    line.decode('utf-8', errors='replace').strip())
        except asyncio.TimeoutError:
            writer.close()
            raise

        if not response_lines:
            writer.close()
            raise WsHandshakeError(0, 'empty response')

        first_line = response_lines[0]
        parts = first_line.split(' ', 2)
        try:
            status_code = int(parts[1]) if len(parts) >= 2 else 0
        except ValueError:
            status_code = 0

        if status_code == 101:
            return RawWebSocket(reader, writer)

        headers: dict[str, str] = {}
        for hl in response_lines[1:]:
            if ':' in hl:
                k, v = hl.split(':', 1)
                headers[k.strip().lower()] = v.strip()

        writer.close()
        raise WsHandshakeError(status_code, first_line, headers,
                                location=headers.get('location'))

    async def send(self, data: bytes):
        """Send a masked binary WebSocket frame."""
        if self._closed:
            raise ConnectionError("WebSocket closed")
        frame = self._build_frame(self.OP_BINARY, data, mask=True)
        self.writer.write(frame)
        await self.writer.drain()

    async def send_batch(self, parts: List[bytes]):
        """Send multiple binary frames with a single drain."""
        if self._closed:
            raise ConnectionError("WebSocket closed")
        for part in parts:
            frame = self._build_frame(self.OP_BINARY, part, mask=True)
            self.writer.write(frame)
        await self.writer.drain()

    async def recv(self) -> Optional[bytes]:
        """
        Receive the next data frame. Handles ping/pong/close internally.
        Returns payload bytes, or None on clean close.
        """
        while not self._closed:
            opcode, payload = await self._read_frame()

            if opcode == self.OP_CLOSE:
                self._closed = True
                try:
                    reply = self._build_frame(
                        self.OP_CLOSE,
                        payload[:2] if payload else b'',
                        mask=True)
                    self.writer.write(reply)
                    await self.writer.drain()
                except Exception:
                    pass
                return None

            if opcode == self.OP_PING:
                try:
                    pong = self._build_frame(self.OP_PONG, payload, mask=True)
                    self.writer.write(pong)
                    await self.writer.drain()
                except Exception:
                    pass
                continue

            if opcode == self.OP_PONG:
                continue

            if opcode in (self.OP_TEXT, self.OP_BINARY):
                return payload

            continue  # unknown opcode — skip

        return None

    async def close(self):
        """Send close frame and shut down the transport."""
        if self._closed:
            return
        self._closed = True
        try:
            self.writer.write(
                self._build_frame(self.OP_CLOSE, b'', mask=True))
            await self.writer.drain()
        except Exception:
            pass
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    @staticmethod
    def _build_frame(opcode: int, data: bytes, mask: bool = False) -> bytes:
        header = bytearray()
        header.append(0x80 | opcode)  # FIN=1 + opcode
        length   = len(data)
        mask_bit = 0x80 if mask else 0x00

        if length < 126:
            header.append(mask_bit | length)
        elif length < 65536:
            header.append(mask_bit | 126)
            header.extend(struct.pack('>H', length))
        else:
            header.append(mask_bit | 127)
            header.extend(struct.pack('>Q', length))

        if mask:
            mask_key = os.urandom(4)
            header.extend(mask_key)
            return bytes(header) + _xor_mask(data, mask_key)
        return bytes(header) + data

    async def _read_frame(self) -> Tuple[int, bytes]:
        hdr     = await self.reader.readexactly(2)
        opcode  = hdr[0] & 0x0F
        is_masked = bool(hdr[1] & 0x80)
        length  = hdr[1] & 0x7F

        if length == 126:
            length = struct.unpack('>H',
                                   await self.reader.readexactly(2))[0]
        elif length == 127:
            length = struct.unpack('>Q',
                                   await self.reader.readexactly(8))[0]

        # FIX-2: Ограничение размера фрейма — защита от OOM/DoS
        if length > MAX_WS_FRAME_SIZE:
            raise ValueError(
                f"WS frame too large: {length} bytes "
                f"(limit {MAX_WS_FRAME_SIZE})")

        if is_masked:
            mask_key = await self.reader.readexactly(4)
            payload  = await self.reader.readexactly(length)
            return opcode, _xor_mask(payload, mask_key)

        payload = await self.reader.readexactly(length)
        return opcode, payload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _human_bytes(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def _exc_text(exc: BaseException) -> str:
    text = str(exc).strip()
    return text or type(exc).__name__


def _is_telegram_ip(ip: str) -> bool:
    try:
        n = struct.unpack('!I', _socket.inet_aton(ip))[0]
        return any(lo <= n <= hi for lo, hi in _TG_RANGES)
    except OSError:
        return False


def _is_http_transport(data: bytes) -> bool:
    return (data[:5] == b'POST ' or data[:4] == b'GET ' or
            data[:5] == b'HEAD ' or data[:8] == b'OPTIONS ')


def _dc_from_init(data: bytes) -> Tuple[Optional[int], bool]:
    """
    Extract DC ID from the 64-byte MTProto obfuscation init packet.
    Returns (dc_id, is_media).
    """
    try:
        key      = bytes(data[8:40])
        iv       = bytes(data[40:56])
        cipher   = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        keystream = encryptor.update(b'\x00' * 64) + encryptor.finalize()
        plain     = bytes(a ^ b for a, b in zip(data[56:64], keystream[56:64]))
        proto     = struct.unpack('<I', plain[0:4])[0]
        dc_raw    = struct.unpack('<h', plain[4:6])[0]
        # FIX-3: Убран plain.hex() из лога — не логируем криптоматериал
        log.debug("dc_from_init: proto=0x%08X dc_raw=%d", proto, dc_raw)
        if proto in (0xEFEFEFEF, 0xEEEEEEEE, 0xDDDDDDDD):
            dc = abs(dc_raw)
            if 1 <= dc <= 1000:
                return dc, (dc_raw < 0)
    except Exception as exc:
        log.debug("DC extraction failed: %s", exc)
    return None, False


def _patch_init_dc(data: bytes, dc: int) -> bytes:
    """
    Patch dc_id in the 64-byte MTProto init packet.

    Mobile clients with useSecret=0 leave bytes 60-61 as random.
    The WS relay needs a valid dc_id to route correctly.
    """
    if len(data) < 64:
        return data

    new_dc = struct.pack('<h', dc)
    try:
        key_raw = bytes(data[8:40])
        iv = bytes(data[40:56])
        cipher = Cipher(algorithms.AES(key_raw), modes.CTR(iv))
        enc = cipher.encryptor()
        ks = enc.update(b'\x00' * 64) + enc.finalize()
        patched = bytearray(data[:64])
        patched[60] = ks[60] ^ new_dc[0]
        patched[61] = ks[61] ^ new_dc[1]
        log.debug("init patched: dc_id -> %d", dc)
        if len(data) > 64:
            return bytes(patched) + data[64:]
        return bytes(patched)
    except Exception:
        return data


class _MsgSplitter:
    """
    Splits client TCP data into individual MTProto abridged-protocol
    messages so each can be sent as a separate WebSocket frame.

    The Telegram WS relay processes one MTProto message per WS frame.
    Mobile clients batch multiple messages in a single TCP write.
    """

    def __init__(self, init_data: bytes):
        key_raw = bytes(init_data[8:40])
        iv = bytes(init_data[40:56])
        cipher = Cipher(algorithms.AES(key_raw), modes.CTR(iv))
        self._dec = cipher.encryptor()
        self._dec.update(b'\x00' * 64)  # skip init packet

    def split(self, chunk: bytes) -> List[bytes]:
        """Decrypt to find message boundaries, return split ciphertext."""
        plain = self._dec.update(chunk)
        boundaries = []
        pos = 0
        while pos < len(plain):
            first = plain[pos]
            if first == 0x7f:
                if pos + 4 > len(plain):
                    break
                msg_len = (
                    struct.unpack_from('<I', plain, pos + 1)[0] & 0xFFFFFF
                ) * 4
                pos += 4
            else:
                msg_len = first * 4
                pos += 1
            if msg_len == 0 or pos + msg_len > len(plain):
                break
            pos += msg_len
            boundaries.append(pos)
        if len(boundaries) <= 1:
            return [chunk]
        parts = []
        prev = 0
        for b in boundaries:
            parts.append(chunk[prev:b])
            prev = b
        if prev < len(chunk):
            parts.append(chunk[prev:])
        return parts


def _ws_domains(dc: int, is_media) -> List[str]:
    """
    Return domain names to try for direct Telegram WebSocket connection.
    DC203 is served under the DC2 hostname. Both kws{N} and kws{N}-1 exist
    under telegram.org, so the media variant is tried first.
    """
    if dc == 203:
        dc = 2
    base = 'telegram.org' if dc > 5 else 'web.telegram.org'
    if is_media is None or is_media:
        return [f'kws{dc}-1.{base}', f'kws{dc}.{base}']
    return [f'kws{dc}.{base}', f'kws{dc}-1.{base}']


# Cloudflare proxies only serve kws{N}.<domain>; there is no kws{N}-1 variant.
# DPI may block the exact SNI, but tolerate the apex domain, so the same host
# is tried twice: first with its real SNI (fully verified), then with the apex
# SNI (still verified against the *.domain wildcard certificate, Host unchanged).
def _cfproxy_hosts(dc: int, is_media) -> List[Tuple[str, str]]:
    """
    Build candidate CF-proxy (host, sni) pairs.
    Each configured base domain becomes kws{dc}.<domain>.

    In 'auto' mode the apex SNI is tried first: DPI commonly filters
    kwsN.<domain> while leaving the apex reachable. Host header stays
    kws{dc}.<domain>, so routing is unchanged; the *.domain certificate
    still verifies for the apex name.
    """
    if not CFPROXY_DOMAINS:
        return []

    if dc == 203:
        dc = 2

    ordered_domains = list(CFPROXY_DOMAINS)
    if CFPROXY_ACTIVE_DOMAIN and CFPROXY_ACTIVE_DOMAIN in ordered_domains:
        ordered_domains = [CFPROXY_ACTIVE_DOMAIN] + [
            d for d in ordered_domains if d != CFPROXY_ACTIVE_DOMAIN
        ]

    hosts: List[Tuple[str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    for base in ordered_domains:
        b = (base or "").strip().lower()
        if not b:
            continue

        host = f'kws{dc}.{b}'
        if b.startswith("kws"):
            candidates = [(b, b)]
        elif CFPROXY_SNI_MODE == "apex":
            candidates = [(host, b)]
        elif CFPROXY_SNI_MODE == "sub":
            candidates = [(host, host)]
        else:
            candidates = [(host, b), (host, host)]

        for pair in candidates:
            if pair in seen:
                continue
            seen.add(pair)
            hosts.append(pair)

    return hosts


def _host_penalized(key: str) -> bool:
    return time.monotonic() < _host_cooldown_until.get(key, 0.0)


def report_host_failure(key: str) -> None:
    failures = _host_fail_counts.get(key, 0) + 1
    _host_fail_counts[key] = failures
    delay = min(HOST_COOLDOWN_INITIAL * 2 ** min(failures - 1, 5),
                HOST_COOLDOWN_MAX)
    _host_cooldown_until[key] = time.monotonic() + delay
    log.debug("Endpoint %s penalized for %.0fs (failures=%d)",
              key, delay, failures)


def report_host_success(key: str) -> None:
    _host_fail_counts.pop(key, None)
    _host_cooldown_until.pop(key, None)


def _cleanup_expired_host_cooldowns():
    now = time.monotonic()
    for host in [h for h, until in _host_cooldown_until.items() if until <= now]:
        _host_cooldown_until.pop(host, None)



class _WsPool:
    WS_POOL_MAX_AGE = 120.0
    REFILL_BACKOFF_INITIAL = 1.0
    REFILL_BACKOFF_MAX = 300.0

    def __init__(self):
        self._idle: Dict[Tuple[int, bool], deque] = {}
        self._refilling: Set[Tuple[int, bool]] = set()
        self._refill_failures: Dict[Tuple[int, bool], int] = {}
        self._refill_after: Dict[Tuple[int, bool], float] = {}

    async def get(self, dc: int, is_media: bool, target_ip: str,
                  domains: List[str]) -> Optional[RawWebSocket]:
        key = (dc, is_media)
        now = time.monotonic()

        bucket = self._idle.get(key)
        if bucket is None:
            bucket = deque()
            self._idle[key] = bucket

        while bucket:
            ws, created = bucket.popleft()
            age = now - created
            if (age > self.WS_POOL_MAX_AGE or ws._closed
                    or ws.writer.transport.is_closing()):
                asyncio.create_task(self._quiet_close(ws))
                continue
            _stats.pool_hits += 1
            self._schedule_refill(key, target_ip, domains)
            return ws

        _stats.pool_misses += 1
        self._schedule_refill(key, target_ip, domains)
        return None

    def _schedule_refill(self, key, target_ip, domains):
        if WS_POOL_SIZE <= 0:
            return
        if _dc_direct_disabled(key[0]):
            return
        if key in self._refilling:
            return
        if time.monotonic() < self._refill_after.get(key, 0):
            return
        self._refilling.add(key)
        asyncio.create_task(self._refill(key, target_ip, domains))

    async def _refill(self, key, target_ip, domains):
        dc = key[0]
        try:
            bucket = self._idle.setdefault(key, deque())
            needed = WS_POOL_SIZE - len(bucket)
            if needed <= 0:
                return
            tasks = [asyncio.create_task(self._connect_one(target_ip, domains))
                     for _ in range(needed)]
            connected = 0
            cert_mismatch = False
            for t in tasks:
                try:
                    ws = await t
                    if ws:
                        bucket.append((ws, time.monotonic()))
                        connected += 1
                except ssl.SSLCertVerificationError:
                    cert_mismatch = True
                except Exception:
                    pass
            if connected:
                self._refill_failures.pop(key, None)
                self._refill_after.pop(key, None)
                return
            # Ни один домен не поднялся. Если direct-WS для этого DC
            # невозможен (сертификат не совпадает с kwsN.*), пул бессмыслен:
            # уходим в долгий backoff, чтобы не спамить лог.
            if cert_mismatch or _dc_direct_disabled(dc):
                if cert_mismatch:
                    _mark_dc_direct_unavailable(
                        dc, 'certificate hostname mismatch')
                self._refill_after[key] = (
                    time.monotonic() + self.REFILL_BACKOFF_MAX)
                return
            failures = self._refill_failures.get(key, 0) + 1
            self._refill_failures[key] = failures
            delay = min(self.REFILL_BACKOFF_INITIAL * 2 ** min(failures - 1, 10),
                        self.REFILL_BACKOFF_MAX)
            self._refill_after[key] = time.monotonic() + delay
            log.info("WS pool refill failed for DC%d%s, retry in %.0fs",
                     key[0], 'm' if key[1] else '', delay)
        finally:
            self._refilling.discard(key)

    @staticmethod
    async def _connect_one(target_ip, domains) -> Optional[RawWebSocket]:
        cert_error = None
        for domain in domains:
            if _host_penalized(domain):
                continue
            try:
                ws = await RawWebSocket.connect(target_ip, domain, timeout=8)
            except ssl.SSLCertVerificationError as exc:
                # DC не отдаёт валидный сертификат на kwsN.web.telegram.org.
                report_host_failure(domain)
                cert_error = exc
                continue
            except Exception:
                report_host_failure(domain)
                continue
            report_host_success(domain)
            return ws
        if cert_error is not None:
            raise cert_error
        return None


    @staticmethod
    async def _quiet_close(ws):
        try:
            await ws.close()
        except Exception:
            pass

    async def warmup(self, dc_redirects: Dict[int, List[str]]):
        if WS_POOL_SIZE <= 0:
            return
        prepared = 0
        for dc, targets in dc_redirects.items():
            if not targets or _dc_direct_disabled(dc):
                continue
            target = targets[0]
            for is_media in (False, True):
                domains = _ws_domains(dc, is_media)
                self._schedule_refill((dc, is_media), target, domains)
            prepared += 1
        if prepared:
            log.info("WS pool warmup started for %d DC(s)", prepared)

    def reset(self):
        self._idle.clear()
        self._refilling.clear()
        self._refill_failures.clear()
        self._refill_after.clear()


_ws_pool = _WsPool()


def _cleanup_expired_cooldowns():
    """FIX-4: Очистка истёкших записей cooldown — нет утечки памяти."""
    now = time.monotonic()
    expired = [k for k, v in _dc_fail_until.items() if v <= now]
    for k in expired:
        del _dc_fail_until[k]
    _cleanup_expired_host_cooldowns()
    for key in [k for k, v in _tcp_retry_after.items() if v <= now]:
        _tcp_retry_after.pop(key, None)
        _tcp_failures.pop(key, None)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class Stats:
    def __init__(self):
        self.connections_total        = 0
        self.connections_active       = 0
        self.connections_ws           = 0
        self.connections_cfproxy      = 0
        self.connections_tcp_fallback = 0
        self.connections_http_rejected = 0
        self.connections_passthrough  = 0
        self.ws_errors                = 0
        self.pool_hits                = 0
        self.pool_misses              = 0
        self.bytes_up                 = 0
        self.bytes_down               = 0

    def summary(self) -> str:
        pool_total = self.pool_hits + self.pool_misses
        pool_s = (f"{self.pool_hits}/{pool_total}" if pool_total else "n/a")
        return (f"total={self.connections_total} active={self.connections_active} "
                f"ws={self.connections_ws} "
                f"cf={self.connections_cfproxy} "
                f"tcp_fb={self.connections_tcp_fallback} "
                f"http_pt={self.connections_http_rejected} "
                f"pass={self.connections_passthrough} "
                f"err={self.ws_errors} "
                f"pool={pool_s} "
                f"up={_human_bytes(self.bytes_up)} "
                f"down={_human_bytes(self.bytes_down)}")


_stats = Stats()


# ---------------------------------------------------------------------------
# Bridging
# ---------------------------------------------------------------------------

async def _bridge_ws(reader, writer, ws: RawWebSocket, label,
                     dc=None, dst=None, port=None, is_media=False,
                     splitter: Optional[_MsgSplitter] = None):
    """Bidirectional TCP <-> WebSocket forwarding."""
    dc_tag  = f"DC{dc}{'m' if is_media else ''}" if dc else "DC?"
    dst_tag = f"{dst}:{port}" if dst else "?"

    up_bytes   = down_bytes   = 0
    up_packets = down_packets = 0
    start_time = asyncio.get_event_loop().time()

    async def tcp_to_ws():
        nonlocal up_bytes, up_packets
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                _stats.bytes_up += len(chunk)
                up_bytes   += len(chunk)
                up_packets += 1
                if splitter:
                    parts = splitter.split(chunk)
                    if len(parts) > 1:
                        await ws.send_batch(parts)
                    else:
                        await ws.send(parts[0])
                else:
                    await ws.send(chunk)
        except (asyncio.CancelledError, ConnectionError, OSError):
            return
        except Exception as e:
            log.debug("[%s] tcp->ws ended: %s", label, e)

    async def ws_to_tcp():
        nonlocal down_bytes, down_packets
        try:
            while True:
                data = await ws.recv()
                if data is None:
                    break
                _stats.bytes_down += len(data)
                down_bytes   += len(data)
                down_packets += 1
                writer.write(data)
                await writer.drain()
        except (asyncio.CancelledError, ConnectionError, OSError):
            return
        except Exception as e:
            log.debug("[%s] ws->tcp ended: %s", label, e)

    tasks = [asyncio.create_task(tcp_to_ws()),
             asyncio.create_task(ws_to_tcp())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        elapsed = asyncio.get_event_loop().time() - start_time
        log.info("[%s] %s (%s) WS session closed: "
                 "^%s (%d pkts) v%s (%d pkts) in %.1fs",
                 label, dc_tag, dst_tag,
                 _human_bytes(up_bytes),   up_packets,
                 _human_bytes(down_bytes), down_packets,
                 elapsed)
        try:
            await ws.close()
        except BaseException:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except BaseException:
            pass


async def _bridge_tcp(reader, writer, remote_reader, remote_writer,
                      label, dc=None, dst=None, port=None, is_media=False):
    """Bidirectional TCP <-> TCP forwarding (fallback)."""
    async def forward(src, dst_w, tag):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                if 'up' in tag:
                    _stats.bytes_up   += len(data)
                else:
                    _stats.bytes_down += len(data)
                dst_w.write(data)
                await dst_w.drain()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.debug("[%s] %s ended: %s", label, tag, e)

    tasks = [
        asyncio.create_task(forward(reader,         remote_writer, 'up')),
        asyncio.create_task(forward(remote_reader,  writer,        'down')),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        for w in (writer, remote_writer):
            try:
                w.close()
                await w.wait_closed()
            except BaseException:
                pass


async def _pipe(r, w):
    """Plain TCP relay for non-Telegram passthrough traffic."""
    try:
        while True:
            data = await r.read(65536)
            if not data:
                break
            w.write(data)
            await w.drain()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass
    finally:
        try:
            w.close()
            await w.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# SOCKS5
# ---------------------------------------------------------------------------

def _socks5_reply(status: int) -> bytes:
    return bytes([0x05, status, 0x00, 0x01]) + b'\x00' * 6


async def _tcp_fallback(reader, writer, dst, port, init, label,
                        dc=None, is_media=False) -> bool:
    """Fall back to direct TCP to the original DC IP (with per-target backoff)."""
    key = (dst, port)
    now = time.monotonic()
    if key in _tcp_connecting or now < _tcp_retry_after.get(key, 0.0):
        log.debug("[%s] TCP fallback to %s:%d skipped (backoff/connecting)",
                  label, dst, port)
        return False

    _tcp_connecting.add(key)
    try:
        try:
            rr, rw = await asyncio.wait_for(
                asyncio.open_connection(dst, port), timeout=10)
            set_sock_opts(rw.transport, SOCKET_BUFFER_SIZE)
        except Exception as exc:
            failures = _tcp_failures.get(key, 0) + 1
            _tcp_failures[key] = failures
            delay = min(TCP_BACKOFF_INITIAL * 2 ** min(failures - 1, 7),
                        TCP_BACKOFF_MAX)
            _tcp_retry_after[key] = time.monotonic() + delay
            log.warning("[%s] TCP fallback connect to %s:%d failed: %s; "
                        "retry in %.0fs", label, dst, port,
                        _exc_text(exc), delay)
            return False
        _tcp_failures.pop(key, None)
        _tcp_retry_after.pop(key, None)
    finally:
        _tcp_connecting.discard(key)

    _stats.connections_tcp_fallback += 1
    rw.write(init)
    await rw.drain()
    await _bridge_tcp(reader, writer, rr, rw, label,
                      dc=dc, dst=dst, port=port, is_media=is_media)
    return True


async def _socks5_authenticate(reader, writer, label: str) -> bool:
    """
    Обрабатывает SOCKS5 аутентификацию (Username/Password).
    Возвращает True если аутентификация успешна, False иначе.
    """
    if not SOCKS5_PASSWORD:
        # Аутентификация не требуется
        return True
    
    try:
        # Клиент отправляет authentication request:
        # +----+------+----------+------+----------+
        # |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        # +----+------+----------+------+----------+
        # | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        # +----+------+----------+------+----------+
        auth_hdr = await asyncio.wait_for(reader.readexactly(2), timeout=5)
        auth_ver = auth_hdr[0]
        ulen = auth_hdr[1]
        
        if auth_ver != 1:
            log.warning("[%s] invalid auth version: %d", label, auth_ver)
            return False
        
        # Прочитаем username
        username = await asyncio.wait_for(reader.readexactly(ulen), timeout=5)
        username = username.decode('utf-8', errors='ignore')
        
        # Прочитаем длину пароля и сам пароль
        plen_byte = await asyncio.wait_for(reader.readexactly(1), timeout=5)
        plen = plen_byte[0]
        password = await asyncio.wait_for(reader.readexactly(plen), timeout=5)
        password = password.decode('utf-8', errors='ignore')
        
        # Проверяем учётные данные
        if username == SOCKS5_USERNAME and password == SOCKS5_PASSWORD:
            # Успешная аутентификация
            # Ответ: VERSION + STATUS (0 = success)
            writer.write(b'\x01\x00')
            await writer.drain()
            log.debug("[%s] SOCKS5 auth successful for user '%s'", label, username)
            return True
        else:
            # Неправильный пароль
            writer.write(b'\x01\x01')  # status = 1 (failed)
            await writer.drain()
            log.warning("[%s] SOCKS5 auth failed for user '%s'", label, username)
            return False
    
    except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
        log.warning("[%s] SOCKS5 auth read failed: %s", label, _exc_text(e))
        return False
    except Exception as e:
        log.warning("[%s] SOCKS5 auth error: %s", label, _exc_text(e))
        return False


async def _handle_client(reader, writer):
    """Entry point for each SOCKS5 connection."""
    global _active_connections, CFPROXY_ACTIVE_DOMAIN

    # FIX-5: Лимит одновременных подключений
    if _active_connections >= MAX_CONNECTIONS:
        log.warning("Connection limit (%d) reached, dropping connection",
                    MAX_CONNECTIONS)
        try:
            writer.close()
        except Exception:
            pass
        return

    _active_connections += 1
    _stats.connections_total += 1
    _stats.connections_active += 1
    peer  = writer.get_extra_info('peername')
    label = f"{peer[0]}:{peer[1]}" if peer else "?"
    set_sock_opts(writer.transport, SOCKET_BUFFER_SIZE)

    try:
        # -- SOCKS5 greeting --
        hdr = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        if hdr[0] != 5:
            log.debug("[%s] not SOCKS5 (ver=%d)", label, hdr[0])
            writer.close()
            return
        nmethods = hdr[1]
        await reader.readexactly(nmethods)
        
        # Выбираем метод аутентификации
        if SOCKS5_PASSWORD:
            # Требуется аутентификация - предлагаем Username/Password (0x02)
            writer.write(b'\x05\x02')  # VERSION + METHOD (0x02 = Username/Password)
            await writer.drain()
            
            # Обрабатываем аутентификацию
            if not await _socks5_authenticate(reader, writer, label):
                writer.close()
                return
        else:
            # Аутентификация не требуется
            writer.write(b'\x05\x00')  # VERSION + METHOD (0x00 = no auth)
            await writer.drain()

        # -- SOCKS5 CONNECT request --
        req = await asyncio.wait_for(reader.readexactly(4), timeout=10)
        _ver, cmd, _rsv, atyp = req
        if cmd != 1:
            writer.write(_socks5_reply(0x07))
            await writer.drain()
            writer.close()
            return

        if atyp == 1:   # IPv4
            raw = await reader.readexactly(4)
            dst = _socket.inet_ntoa(raw)
        elif atyp == 3: # domain
            dlen = (await reader.readexactly(1))[0]
            dst  = (await reader.readexactly(dlen)).decode()
        elif atyp == 4: # IPv6
            raw = await reader.readexactly(16)
            dst = _socket.inet_ntop(_socket.AF_INET6, raw)
        else:
            writer.write(_socks5_reply(0x08))
            await writer.drain()
            writer.close()
            return

        port = struct.unpack('!H', await reader.readexactly(2))[0]

        # -- Non-Telegram IP -> direct passthrough --
        if not _is_telegram_ip(dst):
            _stats.connections_passthrough += 1
            log.debug("[%s] passthrough -> %s:%d", label, dst, port)
            try:
                rr, rw = await asyncio.wait_for(
                    asyncio.open_connection(dst, port), timeout=10)
                set_sock_opts(rw.transport, SOCKET_BUFFER_SIZE)
            except Exception as exc:
                log.warning("[%s] passthrough failed to %s: %s: %s",
                            label, dst, type(exc).__name__,
                            str(exc) or "(no message)")
                writer.write(_socks5_reply(0x05))
                await writer.drain()
                writer.close()
                return

            writer.write(_socks5_reply(0x00))
            await writer.drain()

            tasks = [asyncio.create_task(_pipe(reader, rw)),
                     asyncio.create_task(_pipe(rr, writer))]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in tasks:
                t.cancel()
            for t in tasks:
                try:
                    await t
                except BaseException:
                    pass
            return

        # -- Telegram DC: accept SOCKS, read init --
        writer.write(_socks5_reply(0x00))
        await writer.drain()

        try:
            init = await asyncio.wait_for(
                reader.readexactly(64), timeout=15)
        except asyncio.IncompleteReadError:
            log.debug("[%s] client disconnected before init", label)
            return

        # HTTP transport -> TCP passthrough (CDN/media)
        if _is_http_transport(init):
            _stats.connections_http_rejected += 1
            log.info("[%s] HTTP transport to %s:%d -> TCP passthrough",
                     label, dst, port)
            ok = await _tcp_fallback(reader, writer, dst, port, init, label)
            if ok:
                log.info("[%s] HTTP passthrough closed", label)
            return

        # -- Extract DC ID --
        dc, is_media = _dc_from_init(init)
        init_patched = False
        if dc is None and dst in _IP_TO_DC:
            dc, is_media = _IP_TO_DC.get(dst)
            if dc in _dc_opt:
                init = _patch_init_dc(init, dc if is_media else -dc)
                init_patched = True

        if dc is None or dc not in _dc_opt:
            log.warning("[%s] unknown DC%s for %s:%d -> TCP passthrough",
                        label, dc, dst, port)
            await _tcp_fallback(reader, writer, dst, port, init, label)
            return

        dc_key    = (dc, is_media if is_media is not None else True)
        now       = time.monotonic()
        media_tag = (" media" if is_media
                     else (" media?" if is_media is None else ""))

        # -- WS blacklist check --
        if dc_key in _ws_blacklist:
            log.debug("[%s] DC%d%s WS blacklisted -> TCP %s:%d",
                      label, dc, media_tag, dst, port)
            ok = await _tcp_fallback(reader, writer, dst, port, init,
                                     label, dc=dc, is_media=is_media)
            if ok:
                log.info("[%s] DC%d%s TCP fallback closed",
                         label, dc, media_tag)
            return

        # -- Cooldown check --
        fail_until = _dc_fail_until.get(dc_key, 0)
        if now < fail_until:
            remaining = fail_until - now
            log.debug("[%s] DC%d%s WS cooldown (%.0fs) -> TCP",
                      label, dc, media_tag, remaining)
            ok = await _tcp_fallback(reader, writer, dst, port, init,
                                     label, dc=dc, is_media=is_media)
            if ok:
                log.info("[%s] DC%d%s TCP fallback closed",
                         label, dc, media_tag)
            return

        # -- Try WebSocket --
        domains          = _ws_domains(dc, is_media)
        targets          = _dc_opt[dc]
        cf_hosts         = _cfproxy_hosts(dc, is_media) if CFPROXY_ENABLED else []
        ws               = None
        ws_is_cfproxy    = False
        ws_failed_redirect = False
        all_redirects    = True

        methods = ['direct', 'cfproxy']
        if CFPROXY_PRIORITY:
            methods = ['cfproxy', 'direct']
        pool_media = is_media if is_media is not None else True

        for method in methods:
            if method == 'direct' and _dc_direct_disabled(dc):
                continue
            if method == 'direct':
                for target in targets:
                    ws = await _ws_pool.get(dc, pool_media, target, domains)
                    if ws is not None:
                        all_redirects = False
                        log.info("[%s] DC%d%s (%s:%d) -> pool hit via %s",
                                 label, dc, media_tag, dst, port, target)
                        break

                    for domain in domains:
                        if _host_penalized(domain):
                            continue
                        url = f'wss://{domain}/apiws'
                        log.info("[%s] DC%d%s (%s:%d) -> %s via %s",
                                 label, dc, media_tag, dst, port, url, target)
                        try:
                            ws = await RawWebSocket.connect(target, domain, timeout=10)
                            report_host_success(domain)
                            all_redirects = False
                            break
                        except WsHandshakeError as exc:
                            _stats.ws_errors += 1
                            if exc.is_redirect:
                                ws_failed_redirect = True
                                log.warning("[%s] DC%d%s got %d from %s -> %s",
                                            label, dc, media_tag,
                                            exc.status_code, domain,
                                            exc.location or '?')
                                continue
                            else:
                                all_redirects = False
                                log.warning("[%s] DC%d%s WS handshake: %s",
                                            label, dc, media_tag, exc.status_line)
                        except ssl.SSLCertVerificationError:
                            _stats.ws_errors += 1
                            all_redirects = False
                            _mark_dc_direct_unavailable(
                                dc, 'certificate hostname mismatch')
                        except Exception as exc:
                            _stats.ws_errors += 1
                            all_redirects = False
                            err_str = str(exc)
                            if ('CERTIFICATE_VERIFY_FAILED' in err_str or
                                    'Hostname mismatch' in err_str):
                                log.warning("[%s] DC%d%s SSL error: %s",
                                            label, dc, media_tag, _exc_text(exc))
                            else:
                                log.warning("[%s] DC%d%s WS connect failed: %s",
                                            label, dc, media_tag, _exc_text(exc))
                    if ws is not None:
                        break

            elif method == 'cfproxy' and cf_hosts:
                # Ограничиваем перебор, чтобы один клиент не долбил весь пул
                attempts_left = CF_MAX_ATTEMPTS_PER_REQUEST
                for host, sni in cf_hosts:
                    if attempts_left <= 0:
                        break
                    endpoint = host if sni == host else f'{host}|{sni}'
                    if _host_penalized(endpoint):
                        continue
                    attempts_left -= 1
                    url = f'wss://{host}/apiws'
                    via = '' if sni == host else f' (SNI {sni})'
                    log.info("[%s] DC%d%s (%s:%d) -> %s via DNS%s",
                             label, dc, media_tag, dst, port, url, via)
                    try:
                        ws = await RawWebSocket.connect(host, host, timeout=10,
                                                        sni=sni)
                        report_host_success(endpoint)
                        ws_is_cfproxy = True
                        all_redirects = False
                        break
                    except WsHandshakeError as exc:
                        _stats.ws_errors += 1
                        if exc.is_redirect:
                            ws_failed_redirect = True
                            log.warning("[%s] DC%d%s CF got %d from %s -> %s",
                                        label, dc, media_tag,
                                        exc.status_code, host,
                                        exc.location or '?')
                            continue
                        all_redirects = False
                        report_host_failure(endpoint)
                        log.warning("[%s] DC%d%s CF handshake: %s",
                                    label, dc, media_tag, exc.status_line)
                    except Exception as exc:
                        _stats.ws_errors += 1
                        all_redirects = False
                        report_host_failure(endpoint)
                        err_str = str(exc)
                        if ('CERTIFICATE_VERIFY_FAILED' in err_str or
                                'Hostname mismatch' in err_str):
                            log.warning("[%s] DC%d%s CF SSL error: %s",
                                        label, dc, media_tag, _exc_text(exc))
                        else:
                            log.warning("[%s] DC%d%s CF connect failed: %s",
                                        label, dc, media_tag, _exc_text(exc))
                    if ws is not None:
                        CFPROXY_ACTIVE_DOMAIN = sni
                        break


            if ws is not None:
                break

        # -- WS failed -> fallback --
        if ws is None:
            if ws_failed_redirect and all_redirects:
                _ws_blacklist.add(dc_key)
                log.warning("[%s] DC%d%s blacklisted for WS (all 302)",
                            label, dc, media_tag)
            else:
                _dc_fail_until[dc_key] = now + _DC_FAIL_COOLDOWN
                log.info("[%s] DC%d%s WS cooldown for %ds",
                         label, dc, media_tag, int(_DC_FAIL_COOLDOWN))

            log.info("[%s] DC%d%s -> TCP fallback to %s:%d",
                     label, dc, media_tag, dst, port)
            ok = await _tcp_fallback(reader, writer, dst, port, init,
                                     label, dc=dc, is_media=is_media)
            if ok:
                log.info("[%s] DC%d%s TCP fallback closed",
                         label, dc, media_tag)
            return

        # -- WS success --
        _dc_fail_until.pop(dc_key, None)
        _stats.connections_ws += 1
        if ws_is_cfproxy:
            _stats.connections_cfproxy += 1
        elif targets:
            _ws_pool._schedule_refill((dc, pool_media), targets[0], domains)
        splitter = None
        if init_patched:
            try:
                splitter = _MsgSplitter(init)
            except Exception:
                pass
        await ws.send(init)
        await _bridge_ws(reader, writer, ws, label,
                         dc=dc, dst=dst, port=port, is_media=is_media,
                         splitter=splitter)

    except asyncio.TimeoutError:
        log.warning("[%s] timeout during SOCKS5 handshake", label)
    except asyncio.IncompleteReadError:
        log.debug("[%s] client disconnected", label)
    except asyncio.CancelledError:
        log.debug("[%s] cancelled", label)
    except ConnectionResetError:
        log.debug("[%s] connection reset", label)
    except Exception as exc:
        log.error("[%s] unexpected: %s", label, exc)
    finally:
        _active_connections -= 1
        if _stats.connections_active > 0:
            _stats.connections_active -= 1
        try:
            writer.close()
        except BaseException:
            pass


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

async def _run(port: int, dc_opt: Dict[int, List[str]],
               stop_event: Optional[asyncio.Event] = None,
               host: str = '127.0.0.1'):
    global _dc_opt
    global CFPROXY_DOMAINS, CFPROXY_ACTIVE_DOMAIN
    _dc_opt = dc_opt

    _ws_pool.reset()
    _ws_blacklist.clear()
    _dc_fail_until.clear()
    stop_cfproxy_domain_refresh()

    if CFPROXY_ENABLED:
        CFPROXY_DOMAINS = list(CFPROXY_DOMAINS) or list(CFPROXY_DEFAULT_DOMAINS)
        if not CFPROXY_CUSTOM_DOMAINS and CFPROXY_AUTO_REFRESH:
            start_cfproxy_domain_refresh()
        if CFPROXY_DOMAINS:
            CFPROXY_ACTIVE_DOMAIN = random.choice(CFPROXY_DOMAINS)
    server = await asyncio.start_server(_handle_client, host, port)
    for sock in server.sockets or []:
        try:
            sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass

    log.info("=" * 60)
    log.info("  Telegram WS Bridge Proxy — Secure Edition")
    log.info("  Listening on   %s:%d", host, port)
    log.info("  Target DC IPs:")
    for dc in dc_opt.keys():
        ips = ', '.join(dc_opt.get(dc, []))
        log.info("    DC%d: %s", dc, ips)
    log.info("  Max connections: %d", MAX_CONNECTIONS)
    if CFPROXY_ENABLED and CFPROXY_DOMAINS:
        prio = "CF-first" if CFPROXY_PRIORITY else "direct-first"
        mode = ("custom" if CFPROXY_CUSTOM_DOMAINS
                else ("auto-refresh" if CFPROXY_AUTO_REFRESH else "static"))
        log.info("  CF proxy: %s (%s, %s, active=%s)",
                 ', '.join(CFPROXY_DOMAINS), prio, mode,
                 CFPROXY_ACTIVE_DOMAIN or "-")
    log.info("  Socket buffer: %dKB | WS pool size: %d",
             SOCKET_BUFFER_SIZE // 1024, WS_POOL_SIZE)
    log.info("=" * 60)
    log.info("  Configure Telegram Desktop:")
    if SOCKS5_AUTH_ENABLED:
        # Если запуск через windows.py с аутентификацией
        user = SOCKS5_USERNAME or "user"
        log.info("    SOCKS5 proxy -> %s:%d  (user/pass enabled, user=%s)",
                 host, port, user)
    else:
        # При прямом запуске tg_ws_proxy.py
        log.info("    SOCKS5 proxy -> %s:%d  (no user/pass)", host, port)
    log.info("=" * 60)

    async def log_stats():
        while True:
            await asyncio.sleep(60)
            bl = ', '.join(
                f'DC{d}{"m" if m else ""}'
                for d, m in sorted(_ws_blacklist)) or 'none'
            log.info("stats: %s | ws_bl: %s",
                     _stats.summary(), bl)
            # FIX-4: Периодическая очистка просроченных cooldown-записей
            _cleanup_expired_cooldowns()
            if _host_cooldown_until:
                log.debug("host cooldowns active: %d", len(_host_cooldown_until))

    asyncio.create_task(log_stats())
    await _ws_pool.warmup(dc_opt)

    if stop_event:
        async def wait_stop():
            await stop_event.wait()
            server.close()
            me = asyncio.current_task()
            for task in list(asyncio.all_tasks()):
                if task is not me:
                    task.cancel()
            try:
                await server.wait_closed()
            except asyncio.CancelledError:
                pass
        asyncio.create_task(wait_stop())

    async with server:
        try:
            await server.serve_forever()
        except asyncio.CancelledError:
            pass


def parse_dc_ip_list(dc_ip_list: List[str]) -> Dict[int, List[str]]:
    """Parse list of 'DC:IP' strings into {dc: [ip1, ip2, ...]} dict."""
    dc_opt: Dict[int, List[str]] = {}
    for entry in dc_ip_list:
        if ':' not in entry:
            raise ValueError(
                f"Invalid --dc-ip format {entry!r}, expected DC:IP")
        dc_s, ip_s = entry.split(':', 1)
        try:
            dc_n = int(dc_s)
            _socket.inet_aton(ip_s)
        except (ValueError, OSError):
            raise ValueError(f"Invalid --dc-ip {entry!r}") from None
        if dc_n not in dc_opt:
            dc_opt[dc_n] = []
        if ip_s in dc_opt[dc_n]:
            log.debug("Duplicate DC%d IP ignored: %s", dc_n, ip_s)
            continue
        if dc_opt[dc_n]:
            log.warning("Duplicate DC%d in dc_ip list: adding fallback IP %s",
                        dc_n, ip_s)
        dc_opt[dc_n].append(ip_s)
    return dc_opt


def main():
    ap = argparse.ArgumentParser(
        description='Telegram Desktop WebSocket Bridge Proxy — Secure Edition')
    ap.add_argument('--port', type=int, default=DEFAULT_PORT,
                    help=f'Listen port (default {DEFAULT_PORT})')
    # FIX-6: предупреждение при небезопасном host
    ap.add_argument('--host', type=str, default='127.0.0.1',
                    help='Listen host (default 127.0.0.1). '
                         'WARNING: 0.0.0.0 exposes proxy to the whole network!')
    ap.add_argument('--dc-ip', metavar='DC:IP', action='append',
                    default=[
                        "2:149.154.167.220",
                        "4:149.154.167.92",
                        "203:149.154.167.220"
                    ],
                    help='Target IP for DC, e.g. --dc-ip 2:149.154.167.220')
    ap.add_argument('--buf-kb', type=int, default=DEFAULT_BUF_KB, metavar='KB',
                    help=f'Socket send/recv buffer size in KB (default {DEFAULT_BUF_KB})')
    ap.add_argument('--pool-size', type=int, default=DEFAULT_POOL_SIZE, metavar='N',
                    help=f'WS connection pool size per DC (default {DEFAULT_POOL_SIZE}, min 0)')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='Debug logging')
    ap.add_argument('--cfproxy-enable', action='store_true',
                    help='Enable CF fallback (default domain pool if empty)')
    ap.add_argument('--cfproxy-domain', action='append', default=[],
                    help='CF proxy base domain (repeatable), e.g. example.com')
    ap.add_argument('--cfproxy-priority', action='store_true',
                    help='Try CF proxy before direct WS')
    ap.add_argument('--no-cfproxy-auto-refresh', action='store_true',
                    help='Disable hourly CF domain auto-refresh')
    ap.add_argument('--cfproxy-sni', choices=('auto', 'apex', 'sub'),
                    default='auto',
                    help='SNI for CF connections: auto (domain, then apex '
                         'fallback), apex (always apex, TLS still verified), '
                         'sub (always kwsN.domain)')
    args = ap.parse_args()

    # FIX-6: Предупреждаем если прокси доступен снаружи
    if args.host not in ('127.0.0.1', '::1', 'localhost'):
        print(f"WARNING: Proxy will be accessible on {args.host} — "
              "make sure this is intentional!", file=sys.stderr)

    global CFPROXY_ENABLED, CFPROXY_PRIORITY, CFPROXY_DOMAINS
    global CFPROXY_CUSTOM_DOMAINS, CFPROXY_AUTO_REFRESH, CFPROXY_SNI_MODE
    global SOCKET_BUFFER_SIZE, WS_POOL_SIZE
    CFPROXY_DOMAINS = [d.strip().lower() for d in args.cfproxy_domain
                       if isinstance(d, str) and d.strip()]
    CFPROXY_CUSTOM_DOMAINS = bool(CFPROXY_DOMAINS)
    CFPROXY_PRIORITY = bool(args.cfproxy_priority)
    CFPROXY_AUTO_REFRESH = not bool(args.no_cfproxy_auto_refresh)
    CFPROXY_SNI_MODE = args.cfproxy_sni
    CFPROXY_ENABLED = bool(args.cfproxy_enable or CFPROXY_DOMAINS)
    SOCKET_BUFFER_SIZE = max(4, args.buf_kb) * 1024
    WS_POOL_SIZE = max(0, args.pool_size)

    try:
        dc_opt = parse_dc_ip_list(args.dc_ip)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s  %(levelname)-5s  %(message)s',
        datefmt='%H:%M:%S',
    )

    try:
        asyncio.run(_run(args.port, dc_opt, host=args.host))
    except KeyboardInterrupt:
        log.info("Shutting down. Final stats: %s", _stats.summary())


if __name__ == '__main__':
    main()
