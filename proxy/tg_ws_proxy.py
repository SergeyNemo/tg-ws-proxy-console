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
import logging
import os
import socket as _socket
import ssl
import struct
import sys
import time
from typing import Dict, List, Optional, Set, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


DEFAULT_PORT      = 1080
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

_IP_TO_DC: Dict[str, int] = {
    # DC1
    '149.154.175.50': 1, '149.154.175.51': 1, '149.154.175.54': 1,
    # DC2
    '149.154.167.41': 2,
    '149.154.167.50': 2, '149.154.167.51': 2, '149.154.167.151': 2,
    '149.154.167.220': 2,
    '149.154.167.222': 2,
    # DC3
    '149.154.175.100': 3, '149.154.175.101': 3,
    # DC4
    '149.154.167.91': 4, '149.154.167.92': 4,
    '149.154.164.250': 4,
    # DC5
    '91.108.56.100': 5, '91.108.56.101': 5, '91.108.56.103': 5,
    '91.108.56.116': 5, '91.108.56.126': 5,
    # DC203
    '91.105.192.100': 203,
}

_dc_opt: Dict[int, Optional[str]] = {}

# DCs where WS is known to fail (302 redirect) — TCP fallback will be used
_ws_blacklist: Set[Tuple[int, bool]] = set()

# Rate-limit re-attempts per (dc, is_media)
_dc_fail_until: Dict[Tuple[int, bool], float] = {}
_DC_FAIL_COOLDOWN = 60.0  # seconds

# IPv6 handling
IPV6_MODE = "auto"  # auto | on | off
IPV6_COOLDOWN = 10.0  # seconds to disable IPv6 after failure (auto)
_ipv6_disabled_until = 0.0

# FIX-5: счётчик активных соединений (asyncio однопоточен — нет гонок)
_active_connections: int = 0

# SOCKS5 Authentication — глобальные переменные для логина и пароля
# Устанавливаются из windows.py при запуске
SOCKS5_USERNAME: str = ""
SOCKS5_PASSWORD: str = ""
# Признак включенной аутентификации (нужен для логов)
SOCKS5_AUTH_ENABLED: bool = False

# FIX-1: TLS с полной верификацией — check_hostname=True, verify_mode=CERT_REQUIRED
_ssl_ctx = ssl.create_default_context()
# Значения по умолчанию уже безопасны; явно НЕ отключаем их:
#   _ssl_ctx.check_hostname = True   (default)
#   _ssl_ctx.verify_mode   = ssl.CERT_REQUIRED  (default)


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


class RawWebSocket:
    """
    Lightweight WebSocket client over asyncio reader/writer streams.

    Connects to a target IP or domain via TCP+TLS, performs the HTTP
    Upgrade handshake, and provides send/recv for binary frames with
    masking, ping/pong, and close handling.
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
    async def _handshake(reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter,
                         domain: str,
                         path: str,
                         timeout: float) -> 'RawWebSocket':
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

    @staticmethod
    async def connect_ip(ip: str, domain: str, path: str = '/apiws',
                         timeout: float = 10.0) -> 'RawWebSocket':
        """
        Connect via TLS to ip:443, send SNI=domain,
        perform WebSocket upgrade, return RawWebSocket.
        Raises WsHandshakeError on non-101 response.
        """
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=_ssl_ctx,
                                    server_hostname=domain),
            timeout=min(timeout, 10))
        return await RawWebSocket._handshake(reader, writer, domain,
                                             path, timeout)

    @staticmethod
    async def connect_domain(domain: str, path: str = '/apiws',
                             timeout: float = 10.0) -> 'RawWebSocket':
        """
        Connect via TLS to domain:443 (DNS + SNI),
        perform WebSocket upgrade, return RawWebSocket.
        Raises WsHandshakeError on non-101 response.
        """
        reader, writer = await _open_tls_connection_with_policy(
            domain, 443, timeout=min(timeout, 10))
        return await RawWebSocket._handshake(reader, writer, domain,
                                             path, timeout)

    async def send(self, data: bytes):
        """Send a masked binary WebSocket frame."""
        if self._closed:
            raise ConnectionError("WebSocket closed")
        frame = self._build_frame(self.OP_BINARY, data, mask=True)
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


def _is_telegram_ip(ip: str) -> bool:
    try:
        n = struct.unpack('!I', _socket.inet_aton(ip))[0]
        return any(lo <= n <= hi for lo, hi in _TG_RANGES)
    except OSError:
        return False


def _is_ipv6_address(addr: str) -> bool:
    try:
        _socket.inet_pton(_socket.AF_INET6, addr)
        return True
    except OSError:
        return False


def _ipv6_allowed() -> bool:
    if IPV6_MODE == "on":
        return True
    if IPV6_MODE == "off":
        return False
    return time.monotonic() >= _ipv6_disabled_until


def _mark_ipv6_failure(exc: BaseException) -> None:
    global _ipv6_disabled_until
    if IPV6_MODE != "auto":
        return

    now = time.monotonic()
    if _ipv6_disabled_until > now:
        return

    if isinstance(exc, asyncio.TimeoutError):
        _ipv6_disabled_until = now + IPV6_COOLDOWN
        log.warning("IPv6 timeout; disabling IPv6 for %ds",
                    int(IPV6_COOLDOWN))
        return

    errno = getattr(exc, "errno", None)
    winerr = getattr(exc, "winerror", None)
    if errno in (101, 113, 99, 110) or winerr in (10051, 10065):
        _ipv6_disabled_until = now + IPV6_COOLDOWN
        log.warning("IPv6 unreachable; disabling IPv6 for %ds",
                    int(IPV6_COOLDOWN))


def _is_tls_error(exc: BaseException) -> bool:
    if isinstance(exc, ssl.SSLError):
        return True
    err = str(exc)
    return any(token in err for token in (
        "RECORD_LAYER_FAILURE",
        "WRONG_VERSION_NUMBER",
        "TLSV1_ALERT",
        "CERTIFICATE_VERIFY_FAILED",
        "Hostname mismatch",
    ))


async def _open_connection_with_policy(host: str, port: int,
                                       timeout: float = 10.0):
    """Resolve and connect honoring IPv6 policy. Returns (reader, writer)."""
    allow_ipv6 = _ipv6_allowed()

    # IPv4 literal
    try:
        _socket.inet_aton(host)
        return await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except OSError:
        pass

    # IPv6 literal
    if _is_ipv6_address(host):
        if not allow_ipv6:
            raise OSError(101, "IPv6 disabled")
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(host, port, family=_socket.AF_INET6),
                timeout=timeout)
        except Exception as exc:
            _mark_ipv6_failure(exc)
            raise

    # Domain name: resolve and attempt
    infos = await asyncio.get_event_loop().getaddrinfo(
        host, port, type=_socket.SOCK_STREAM, family=_socket.AF_UNSPEC)
    addrs = []
    for family, socktype, proto, _canon, sockaddr in infos:
        if family == _socket.AF_INET6 and not allow_ipv6:
            continue
        addrs.append((family, socktype, proto, sockaddr))

    if allow_ipv6:
        addrs.sort(key=lambda x: 0 if x[0] == _socket.AF_INET6 else 1)

    last_exc = None
    for family, _socktype, _proto, sockaddr in addrs:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(sockaddr[0], sockaddr[1],
                                        family=family),
                timeout=timeout)
        except Exception as exc:
            last_exc = exc
            if family == _socket.AF_INET6:
                _mark_ipv6_failure(exc)
            continue

    if last_exc:
        raise last_exc
    raise OSError("No resolved addresses")


async def _open_tls_connection_with_policy(domain: str, port: int,
                                           timeout: float = 10.0):
    """Resolve domain and connect via TLS honoring IPv6 policy."""
    allow_ipv6 = _ipv6_allowed()
    infos = await asyncio.get_event_loop().getaddrinfo(
        domain, port, type=_socket.SOCK_STREAM, family=_socket.AF_UNSPEC)
    addrs = []
    for family, socktype, proto, _canon, sockaddr in infos:
        if family == _socket.AF_INET6 and not allow_ipv6:
            continue
        addrs.append((family, socktype, proto, sockaddr))

    if allow_ipv6:
        addrs.sort(key=lambda x: 0 if x[0] == _socket.AF_INET6 else 1)

    last_exc = None
    for family, _socktype, _proto, sockaddr in addrs:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(sockaddr[0], sockaddr[1],
                                        ssl=_ssl_ctx,
                                        server_hostname=domain,
                                        family=family),
                timeout=timeout)
        except Exception as exc:
            last_exc = exc
            if family == _socket.AF_INET6:
                _mark_ipv6_failure(exc)
            continue

    if last_exc:
        raise last_exc
    raise OSError("No resolved addresses")

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


def _ws_domains(dc: int, is_media) -> List[str]:
    """
    Return domain names to try for WebSocket connection to a DC.
    DC 1-5:  kws{N}[-1].web.telegram.org
    DC >5:   kws{N}[-1].telegram.org
    """
    base = 'telegram.org' if dc > 5 else 'web.telegram.org'
    if is_media is None or is_media:
        return [f'kws{dc}-1.{base}', f'kws{dc}.{base}']
    return [f'kws{dc}.{base}', f'kws{dc}-1.{base}']


def _cleanup_expired_cooldowns():
    """FIX-4: Очистка истёкших записей cooldown — нет утечки памяти."""
    now = time.monotonic()
    expired = [k for k, v in _dc_fail_until.items() if v <= now]
    for k in expired:
        del _dc_fail_until[k]


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class Stats:
    def __init__(self):
        self.connections_total        = 0
        self.connections_ws           = 0
        self.connections_tcp_fallback = 0
        self.connections_http_rejected = 0
        self.connections_passthrough  = 0
        self.ws_errors                = 0
        self.bytes_up                 = 0
        self.bytes_down               = 0

    def summary(self) -> str:
        return (f"total={self.connections_total} ws={self.connections_ws} "
                f"tcp_fb={self.connections_tcp_fallback} "
                f"http_skip={self.connections_http_rejected} "
                f"pass={self.connections_passthrough} "
                f"err={self.ws_errors} "
                f"up={_human_bytes(self.bytes_up)} "
                f"down={_human_bytes(self.bytes_down)}")


_stats = Stats()


# ---------------------------------------------------------------------------
# Bridging
# ---------------------------------------------------------------------------

async def _bridge_ws(reader, writer, ws: RawWebSocket, label,
                     dc=None, dst=None, port=None, is_media=False):
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
    """Fall back to direct TCP to the original DC IP."""
    try:
        rr, rw = await _open_connection_with_policy(dst, port, timeout=10)
    except Exception as exc:
        log.warning("[%s] TCP fallback connect to %s:%d failed: %s",
                    label, dst, port, exc)
        return False

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
        log.warning("[%s] SOCKS5 auth read failed: %s", label, e)
        return False
    except Exception as e:
        log.warning("[%s] SOCKS5 auth error: %s", label, e)
        return False


async def _handle_client(reader, writer):
    """Entry point for each SOCKS5 connection."""
    global _active_connections

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
    peer  = writer.get_extra_info('peername')
    label = f"{peer[0]}:{peer[1]}" if peer else "?"

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
        dst_is_ipv6 = (atyp == 4)

        if dst_is_ipv6 and not _ipv6_allowed():
            log.debug("[%s] IPv6 disabled -> reject %s:%d", label, dst, port)
            writer.write(_socks5_reply(0x08))  # address type not supported
            await writer.drain()
            writer.close()
            return

        # -- Non-Telegram IP -> direct passthrough --
        if not _is_telegram_ip(dst):
            _stats.connections_passthrough += 1
            log.debug("[%s] passthrough -> %s:%d", label, dst, port)
            try:
                rr, rw = await _open_connection_with_policy(
                    dst, port, timeout=10)
            except Exception as exc:
                log.warning("[%s] passthrough failed to %s: %s: %s",
                            label, dst, type(exc).__name__,
                            str(exc) or "(no message)")
                if dst_is_ipv6 and IPV6_MODE != "on":
                    writer.write(_socks5_reply(0x08))  # address type not supported
                else:
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

        # HTTP transport -> reject
        if _is_http_transport(init):
            _stats.connections_http_rejected += 1
            log.debug("[%s] HTTP transport to %s:%d (rejected)",
                      label, dst, port)
            writer.close()
            return

        # -- Extract DC ID --
        dc, is_media = _dc_from_init(init)
        if dc is None and dst in _IP_TO_DC:
            dc = _IP_TO_DC.get(dst)

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
        target           = _dc_opt[dc]
        ws               = None
        ws_failed_redirect = False
        all_redirects    = True

        for domain in domains:
            url = f'wss://{domain}/apiws'
            via = target or "DNS"
            log.info("[%s] DC%d%s (%s:%d) -> %s via %s",
                     label, dc, media_tag, dst, port, url, via)
            try:
                if target:
                    try:
                        ws = await RawWebSocket.connect_ip(
                            target, domain, timeout=10)
                    except Exception as exc:
                        if _is_tls_error(exc):
                            all_redirects = False
                            log.warning("[%s] DC%d%s TLS error via %s, retry via DNS: %s",
                                        label, dc, media_tag, target, exc)
                            ws = await RawWebSocket.connect_domain(
                                domain, timeout=10)
                        else:
                            raise
                else:
                    ws = await RawWebSocket.connect_domain(
                        domain, timeout=10)
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
            except Exception as exc:
                _stats.ws_errors += 1
                all_redirects = False
                err_str = str(exc)
                if ('CERTIFICATE_VERIFY_FAILED' in err_str or
                        'Hostname mismatch' in err_str):
                    log.warning("[%s] DC%d%s SSL error: %s",
                                label, dc, media_tag, exc)
                else:
                    log.warning("[%s] DC%d%s WS connect failed: %s",
                                label, dc, media_tag, exc)

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
        await ws.send(init)
        await _bridge_ws(reader, writer, ws, label,
                         dc=dc, dst=dst, port=port, is_media=is_media)

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
        try:
            writer.close()
        except BaseException:
            pass


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

_server_instance   = None
_server_stop_event = None


async def _run(port: int, dc_opt: Dict[int, Optional[str]],
               stop_event: Optional[asyncio.Event] = None,
               host: str = '127.0.0.1'):
    global _dc_opt, _server_instance, _server_stop_event
    _dc_opt            = dc_opt
    _server_stop_event = stop_event

    server           = await asyncio.start_server(_handle_client, host, port)
    _server_instance = server

    log.info("=" * 60)
    log.info("  Telegram WS Bridge Proxy — Secure Edition")
    log.info("  Listening on   %s:%d", host, port)
    log.info("  Target DC IPs:")
    for dc in dc_opt.keys():
        log.info("    DC%d: %s", dc, dc_opt.get(dc))
    log.info("  Max connections: %d", MAX_CONNECTIONS)
    log.info("  IPv6 mode: %s (cooldown %ds)", IPV6_MODE, int(IPV6_COOLDOWN))
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
            log.info("stats: %s | ws_bl: %s | active: %d",
                     _stats.summary(), bl, _active_connections)
            # FIX-4: Периодическая очистка просроченных cooldown-записей
            _cleanup_expired_cooldowns()

    asyncio.create_task(log_stats())

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
    _server_instance = None


def parse_dc_ip_list(dc_ip_list: List[str]) -> Dict[int, str]:
    """Parse list of 'DC:IP' strings into {dc: ip} dict."""
    dc_opt: Dict[int, str] = {}
    for entry in dc_ip_list:
        if ':' not in entry:
            raise ValueError(
                f"Invalid --dc-ip format {entry!r}, expected DC:IP")
        dc_s, ip_s = entry.split(':', 1)
        try:
            dc_n = int(dc_s)
            _socket.inet_aton(ip_s)
        except (ValueError, OSError):
            raise ValueError(f"Invalid --dc-ip {entry!r}")
        dc_opt[dc_n] = ip_s
    return dc_opt


# Public alias for external use (called from windows.py)
handle_client = _handle_client



def run_proxy(port: int, dc_opt: Dict[int, str],
              stop_event: Optional[asyncio.Event] = None,
              host: str = '127.0.0.1'):
    """Run the proxy (blocking). Called from GUI thread."""
    asyncio.run(_run(port, dc_opt, stop_event, host))


def main():
    global IPV6_MODE, IPV6_COOLDOWN, _ipv6_disabled_until
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
                        "1:149.154.175.50", "1:149.154.175.51", "1:149.154.175.54",
                        "2:149.154.167.41", "2:149.154.167.50", "2:149.154.167.51",
                        "2:149.154.167.151", "2:149.154.167.222", "2:149.154.167.220",
                        "3:149.154.175.100", "3:149.154.175.101",
                        "4:149.154.167.91", "4:149.154.164.250", "4:149.154.167.92",
                        "5:91.108.56.100", "5:91.108.56.101", "5:91.108.56.103",
                        "5:91.108.56.116", "5:91.108.56.126"
                    ],
                    help='Target IP for DC, e.g. --dc-ip 2:149.154.167.220')
    ap.add_argument('--ipv6', choices=['auto', 'on', 'off'], default='auto',
                    help='IPv6 handling: auto (disable on errors), on, off')
    ap.add_argument('--ipv6-cooldown', type=int, default=int(IPV6_COOLDOWN),
                    help='Seconds to disable IPv6 after failure (auto mode)')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='Debug logging')
    args = ap.parse_args()

    # FIX-6: Предупреждаем если прокси доступен снаружи
    if args.host not in ('127.0.0.1', '::1', 'localhost'):
        print(f"WARNING: Proxy will be accessible on {args.host} — "
              "make sure this is intentional!", file=sys.stderr)

    IPV6_MODE = args.ipv6
    IPV6_COOLDOWN = max(10.0, float(args.ipv6_cooldown))
    _ipv6_disabled_until = 0.0

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
