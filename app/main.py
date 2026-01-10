import asyncio
import json
import os
import re
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import Dict, Optional, List

import pymysql
from dateutil import parser as dtparser

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, PlainTextResponse

# Optional GeoIP (für NTOP -> Land)
try:
    from geoip2.database import Reader as GeoIPReader
    from geoip2.errors import AddressNotFoundError
except Exception:  # pragma: no cover
    GeoIPReader = None
    AddressNotFoundError = Exception

from zoneinfo import ZoneInfo

# ============================================================
# Config via ENV
# ============================================================
LOG_GEO = os.getenv("LOG_GEO", "/logs/geo_block.log")
LOG_NTOP = os.getenv("LOG_NTOP", "/logs/ntop_alerts.log")
LOG_STREAM = os.getenv("LOG_STREAM", "/logs/stream_logs.log")

STATE_DIR = os.getenv("STATE_DIR", "/data")
STATE_FILE = os.path.join(STATE_DIR, "state.json")

DB_HOST = os.getenv("DB_HOST", "mariadb")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "geo")
DB_PASS = os.getenv("DB_PASS", "geo")
DB_NAME = os.getenv("DB_NAME", "geo")

RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))
RETENTION_RUN_EVERY_SEC = int(os.getenv("RETENTION_RUN_EVERY_SEC", str(6 * 3600)))  # alle 6h

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "0.5"))
READ_FROM_START = os.getenv("READ_FROM_START", "0") == "1"
MAX_LATEST_LINES = int(os.getenv("MAX_LATEST_LINES", "800"))

GEOIP_MMDB = os.getenv("GEOIP_MMDB", "").strip()


# ============================================================
# Helpers
# ============================================================
def now_utc_naive() -> datetime:
    return datetime.utcnow().replace(tzinfo=None)


def ip_bytes_to_str(b: bytes) -> str:
    try:
        if len(b) == 4:
            return str(IPv4Address(b))
        if len(b) == 16:
            return str(IPv6Address(b))
    except Exception:
        pass
    return b.hex()


def normalize_log_source(path: str) -> str:
    if path == LOG_GEO:
        return "geo"
    if path == LOG_NTOP:
        return "ntop"
    if path == LOG_STREAM:
        return "stream"
    return "other"


def prefix_for_source(source: str) -> str:
    if source == "geo":
        return "GEO-BLOCKING: "
    if source == "ntop":
        return "NTOP-BLACKLIST: "
    if source == "stream":
        return "NPM-STREAM-LOG: "
    return "LOG: "


def clamp_hours(hours: int) -> int:
    return max(1, min(int(hours), 24 * 30))


def clamp_limit(limit: int, lo: int, hi: int) -> int:
    return max(lo, min(int(limit), hi))


def safe_int(x: Optional[str]) -> Optional[int]:
    try:
        return int(x) if x is not None else None
    except Exception:
        return None

import urllib.request

COUNTRY_CODES_URL = os.getenv(
    "COUNTRY_CODES_URL",
    "https://www.xrepository.de/api/xrepository/urn:xoev-de:kosit:codeliste:country-codes_8/download/Country_Codes_8.json",
).strip()
COUNTRY_CODES_CACHE = os.getenv("COUNTRY_CODES_CACHE", os.path.join(STATE_DIR, "Country_Codes_8.json")).strip()

# Wird beim Startup gefüllt:
ISO2_META: Dict[str, Dict[str, str]] = {}  # {"DE": {"country":"DE","country_name":"Deutschland","flag":"🇩🇪"}, ...}


def _download_country_codes_sync(url: str, dest: str) -> bool:
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with urllib.request.urlopen(url, timeout=20) as r:
            data = r.read()
        with open(dest, "wb") as f:
            f.write(data)
        return True
    except Exception:
        return False


def iso2_to_flag(iso2: str) -> str:
    # ISO2 -> Regional Indicator Symbols (🇩🇪 etc.)
    if not iso2 or len(iso2) != 2:
        return ""
    iso2 = iso2.upper()
    if not ("A" <= iso2[0] <= "Z" and "A" <= iso2[1] <= "Z"):
        return ""
    return chr(0x1F1E6 + (ord(iso2[0]) - ord("A"))) + chr(0x1F1E6 + (ord(iso2[1]) - ord("A")))


def _load_country_codes_sync(path: str) -> Dict[str, Dict[str, str]]:
    """
    Liest XRepository Country_Codes_8.json:
      - spalten: enthält Index-Infos
      - daten: rows als arrays
    Wir bauen ISO2 -> ShortName (DE) + Flag.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            j = json.load(f)

        cols = j.get("spalten") or []
        col_index = {}
        for idx, c in enumerate(cols):
            # "spaltennameTechnisch": "ISOAlpha2code", "ShortName", ...
            key = (c.get("spaltennameTechnisch") or "").strip()
            if key:
                col_index[key] = idx

        i_iso2 = col_index.get("ISOAlpha2code")
        i_short = col_index.get("ShortName")
        i_full = col_index.get("FullName")

        if i_iso2 is None:
            return {}

        out: Dict[str, Dict[str, str]] = {}
        for row in (j.get("daten") or []):
            try:
                iso2 = (row[i_iso2] or "").strip().upper()
                if not iso2 or len(iso2) != 2:
                    continue
                name = None
                if i_short is not None:
                    name = row[i_short]
                if not name and i_full is not None:
                    name = row[i_full]
                name = (name or iso2).strip()

                out[iso2] = {
                    "country": iso2,
                    "country_name": name,
                    "flag": iso2_to_flag(iso2),
                }
            except Exception:
                continue

        return out
    except Exception:
        return {}


async def load_country_codes():
    global ISO2_META

    # 1) Cache lesen
    if os.path.exists(COUNTRY_CODES_CACHE):
        ISO2_META = await asyncio.to_thread(_load_country_codes_sync, COUNTRY_CODES_CACHE)
        if ISO2_META:
            return

    # 2) Download versuchen
    ok = await asyncio.to_thread(_download_country_codes_sync, COUNTRY_CODES_URL, COUNTRY_CODES_CACHE)
    if ok:
        ISO2_META = await asyncio.to_thread(_load_country_codes_sync, COUNTRY_CODES_CACHE)

    # 3) Notfall: wenigstens DE/US etc. nicht komplett leer
    if not ISO2_META:
        ISO2_META = {
            "DE": {"country": "DE", "country_name": "Deutschland", "flag": "🇩🇪"},
            "US": {"country": "US", "country_name": "Vereinigte Staaten", "flag": "🇺🇸"},
            "NL": {"country": "NL", "country_name": "Niederlande", "flag": "🇳🇱"},
            "FR": {"country": "FR", "country_name": "Frankreich", "flag": "🇫🇷"},
            "GB": {"country": "GB", "country_name": "Vereinigtes Königreich", "flag": "🇬🇧"},
        }


def country_meta(iso2: str) -> dict:
    iso2 = (iso2 or "").upper()
    if iso2 in ISO2_META:
        return ISO2_META[iso2]
    # Fallback (?? etc.)
    return {
        "country": iso2,
        "country_name": iso2 if iso2 else "??",
        "flag": iso2_to_flag(iso2),
    }

# ============================================================
# Regexes
# ============================================================
GEO_RE = re.compile(
    r"^(?P<ts>\S+)\s+INFO\s+IP\s+(?P<ip>[0-9a-fA-F\.:]+)\s+\(Proxy\)\s+geblockt\s+\|\s+Ursprungsland\s+=\s+(?P<country>[A-Z]{2})\s+\|\s+Ziel-URL\s+=\s+(?P<url>.+)$"
)

# NTOP Logs kommen bei dir teils schon mit Prefix aus Viewer – wir entfernen das.
NTOP_LINE_PREFIX_RE = re.compile(r"^(?:NTOP-BLACKLIST:\s*)?(?P<rest>.+)$")

NTOP_BLOCKED_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\d+\s+INFO\s+IP\s+(?P<ip>[0-9a-fA-F\.:]+)\s+geblockt\s+\(gesamt:\s+(?P<total>\d+)\s+IPs\)\s*$"
)

NTOP_ALREADY_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\d+\s+INFO\s+IP\s+(?P<ip>[0-9a-fA-F\.:]+)\s+bereits\s+geblockt\s+\(zuletzt\s+(?P<last>\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}:\d{2})\s+\w+,"
)

NTOP_EXPIRED_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\d+\s+INFO\s+Abgelaufene\s+IP\s+(?P<ip>[0-9a-fA-F\.:]+)\s+nach\s+(?P<ttl>\d+)\s+Tagen\s+TTL\s+entfernt\s+\(verbleibend:\s+(?P<remaining>\d+)\s+IPs\)\s*$"
)


def parse_local_dt(s: str) -> Optional[datetime]:
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def parse_last_seen_local(s: str) -> Optional[datetime]:
    try:
        return datetime.strptime(s, "%d.%m.%Y %H:%M:%S")
    except Exception:
        return None


# ============================================================
# GeoIP Resolver (optional)
# ============================================================
_geoip_reader = None


def geoip_country_code(ip_str: str) -> Optional[str]:
    global _geoip_reader
    if not GEOIP_MMDB:
        return None
    if GeoIPReader is None:
        return None
    try:
        if _geoip_reader is None:
            _geoip_reader = GeoIPReader(GEOIP_MMDB)
        resp = _geoip_reader.country(ip_str)
        code = getattr(resp.country, "iso_code", None)
        return code
    except AddressNotFoundError:
        return None
    except Exception:
        return None


# ============================================================
# State store (inode/offset)
# ============================================================
@dataclass
class FileState:
    inode: Optional[int] = None
    offset: int = 0
    initialized: bool = False


class StateStore:
    def __init__(self, path: str):
        self.path = path
        self.lock = asyncio.Lock()
        self.state: Dict[str, FileState] = {}

    def _load_sync(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        if not os.path.exists(self.path):
            self.state = {}
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            out: Dict[str, FileState] = {}
            for k, v in raw.items():
                out[k] = FileState(
                    inode=v.get("inode"),
                    offset=int(v.get("offset", 0)),
                    initialized=bool(v.get("initialized", False)),
                )
            self.state = out
        except Exception:
            self.state = {}

    async def load(self) -> None:
        await asyncio.to_thread(self._load_sync)

    def _save_sync(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        raw = {k: {"inode": v.inode, "offset": v.offset, "initialized": v.initialized} for k, v in self.state.items()}
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(raw, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    async def save(self) -> None:
        async with self.lock:
            await asyncio.to_thread(self._save_sync)

    async def get(self, key: str) -> FileState:
        async with self.lock:
            if key not in self.state:
                self.state[key] = FileState()
            return self.state[key]

    async def update(self, key: str, inode: int, offset: int, initialized: bool) -> None:
        async with self.lock:
            self.state[key] = FileState(inode=inode, offset=offset, initialized=initialized)
        await self.save()


# ============================================================
# DB wrapper (robust): Connection pro Query
# ============================================================
class DB:
    def __init__(self):
        self._schema_ready = False
        self._schema_lock = asyncio.Lock()

    def _connect_sync(self):
        return pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME,
            autocommit=True,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
        )

    def _run_sync(self, sql: str, args=None, fetch: str = "none"):
        conn = self._connect_sync()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, args)
                if fetch == "one":
                    return cur.fetchone()
                if fetch == "all":
                    return cur.fetchall()
                return None
        finally:
            try:
                conn.close()
            except Exception:
                pass

    async def connect(self):
        async with self._schema_lock:
            if self._schema_ready:
                return
            await self._ensure_schema()
            self._schema_ready = True

    async def _ensure_schema(self):
        await asyncio.to_thread(
            self._run_sync,
            """
            CREATE TABLE IF NOT EXISTS geo_blocks (
              id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
              ts_utc DATETIME NOT NULL,
              ip VARBINARY(16) NOT NULL,
              country CHAR(2) NOT NULL,
              url VARCHAR(2048) NOT NULL,
              raw_line VARCHAR(4096) NOT NULL,
              created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
              KEY idx_ts (ts_utc),
              KEY idx_country_ts (country, ts_utc),
              KEY idx_ip_ts (ip, ts_utc),
              KEY idx_url_ts (url(191), ts_utc)
            );
            """,
            None,
            "none",
        )

        await asyncio.to_thread(
            self._run_sync,
            """
            CREATE TABLE IF NOT EXISTS ntop_blacklist_events (
              id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
              ts_local DATETIME NOT NULL,
              action ENUM('blocked','already_blocked','expired_removed','other') NOT NULL,
              ip VARBINARY(16) NULL,
              last_seen_local DATETIME NULL,
              ttl_days INT NULL,
              remaining_ips INT NULL,
              total_ips INT NULL,
              country CHAR(2) NULL,
              raw_line VARCHAR(4096) NOT NULL,
              created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
              KEY idx_ts (ts_local),
              KEY idx_action_ts (action, ts_local),
              KEY idx_ip_ts (ip, ts_local),
              KEY idx_country_ts (country, ts_local)
            );
            """,
            None,
            "none",
        )

        # Migration safety (falls du früher ohne country/url index deployed hattest)
        try:
            await asyncio.to_thread(self._run_sync, "ALTER TABLE ntop_blacklist_events ADD COLUMN country CHAR(2) NULL", None, "none")
        except Exception:
            pass
        try:
            await asyncio.to_thread(self._run_sync, "ALTER TABLE ntop_blacklist_events ADD KEY idx_country_ts (country, ts_local)", None, "none")
        except Exception:
            pass
        try:
            await asyncio.to_thread(self._run_sync, "ALTER TABLE geo_blocks ADD KEY idx_url_ts (url(191), ts_utc)", None, "none")
        except Exception:
            pass

    async def exec(self, sql: str, args=None):
        await self.connect()
        return await asyncio.to_thread(self._run_sync, sql, args, "none")

    async def fetchone(self, sql: str, args=None):
        await self.connect()
        return await asyncio.to_thread(self._run_sync, sql, args, "one")

    async def fetchall(self, sql: str, args=None):
        await self.connect()
        return await asyncio.to_thread(self._run_sync, sql, args, "all")

    async def insert_geo(self, ts_utc: datetime, ip_bytes: bytes, country: str, url: str, raw_line: str):
        await self.exec(
            """
            INSERT INTO geo_blocks (ts_utc, ip, country, url, raw_line)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (ts_utc.strftime("%Y-%m-%d %H:%M:%S"), ip_bytes, country, url[:2048], raw_line[:4096]),
        )

    async def insert_ntop(
        self,
        ts_local: datetime,
        action: str,
        ip_bytes: Optional[bytes],
        last_seen_local: Optional[datetime],
        ttl_days: Optional[int],
        remaining_ips: Optional[int],
        total_ips: Optional[int],
        country: Optional[str],
        raw_line: str,
    ):
        def fmt(dt: Optional[datetime]) -> Optional[str]:
            return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else None

        await self.exec(
            """
            INSERT INTO ntop_blacklist_events
              (ts_local, action, ip, last_seen_local, ttl_days, remaining_ips, total_ips, country, raw_line)
            VALUES
              (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                ts_local.strftime("%Y-%m-%d %H:%M:%S"),
                action,
                ip_bytes,
                fmt(last_seen_local),
                ttl_days,
                remaining_ips,
                total_ips,
                country,
                raw_line[:4096],
            ),
        )

    async def retention_cleanup(self):
        await self.exec("DELETE FROM geo_blocks WHERE ts_utc < (UTC_TIMESTAMP() - INTERVAL %s DAY)", (RETENTION_DAYS,))
        await self.exec("DELETE FROM ntop_blacklist_events WHERE ts_local < (NOW() - INTERVAL %s DAY)", (RETENTION_DAYS,))


# ============================================================
# SSE broadcaster
# ============================================================
class Broadcaster:
    def __init__(self, max_queue=2500):
        self.clients: List[asyncio.Queue] = []
        self.lock = asyncio.Lock()
        self.max_queue = max_queue

    async def register(self) -> asyncio.Queue:
        q = asyncio.Queue(maxsize=self.max_queue)
        async with self.lock:
            self.clients.append(q)
        return q

    async def unregister(self, q: asyncio.Queue):
        async with self.lock:
            if q in self.clients:
                self.clients.remove(q)

    async def publish(self, source: str, line: str):
        async with self.lock:
            clients = list(self.clients)
        msg = {"source": source, "line": line}
        raw = json.dumps(msg, ensure_ascii=False)
        for q in clients:
            try:
                q.put_nowait(raw)
            except asyncio.QueueFull:
                try:
                    _ = q.get_nowait()
                except Exception:
                    pass
                try:
                    q.put_nowait(raw)
                except Exception:
                    pass


# ============================================================
# Tailer
# ============================================================
def time_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


async def tail_file_forever(path: str, state_store: StateStore, broadcaster: Broadcaster, db: DB, latest_buf: deque):
    key = os.path.abspath(path)
    source = normalize_log_source(path)
    pref = prefix_for_source(source)

    while True:
        try:
            st = os.stat(path)
            inode = st.st_ino
            size = st.st_size

            fs = await state_store.get(key)

            if fs.inode is None or fs.inode != inode:
                if not fs.initialized:
                    offset = 0 if READ_FROM_START else size
                    initialized = True
                else:
                    offset = 0
                    initialized = True
                await state_store.update(key, inode, offset, initialized)
                fs = await state_store.get(key)

            if size < fs.offset:
                await state_store.update(key, inode, 0, True)
                fs = await state_store.get(key)

            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(fs.offset)

                while True:
                    line = f.readline()
                    if line:
                        fs.offset = f.tell()
                        await state_store.update(key, inode, fs.offset, True)

                        line = line.rstrip("\n")
                        if not line.strip():
                            continue

                        display_line = pref + line
                        latest_buf.append({"ts": time_iso(), "source": source, "line": display_line})
                        await broadcaster.publish(source, display_line)

                        if source == "geo":
                            m = GEO_RE.match(line)
                            if m:
                                try:
                                    ts_utc = dtparser.isoparse(m.group("ts")).astimezone(timezone.utc).replace(tzinfo=None)
                                    ipb = ip_address(m.group("ip")).packed
                                    country = m.group("country")
                                    url = m.group("url")
                                    await db.insert_geo(ts_utc, ipb, country, url, line)
                                except Exception:
                                    pass

                        elif source == "ntop":
                            mm = NTOP_LINE_PREFIX_RE.match(line)
                            rest = mm.group("rest") if mm else line

                            try:
                                m1 = NTOP_BLOCKED_RE.match(rest)
                                m2 = NTOP_ALREADY_RE.match(rest)
                                m3 = NTOP_EXPIRED_RE.match(rest)

                                if m1:
                                    ts_local = parse_local_dt(m1.group("ts"))
                                    ip_str = m1.group("ip")
                                    ipb = ip_address(ip_str).packed
                                    total = safe_int(m1.group("total"))
                                    cc = geoip_country_code(ip_str)
                                    if ts_local:
                                        await db.insert_ntop(ts_local, "blocked", ipb, None, None, None, total, cc, rest)

                                elif m2:
                                    ts_local = parse_local_dt(m2.group("ts"))
                                    ip_str = m2.group("ip")
                                    ipb = ip_address(ip_str).packed
                                    last_seen = parse_last_seen_local(m2.group("last"))
                                    cc = geoip_country_code(ip_str)
                                    if ts_local:
                                        await db.insert_ntop(ts_local, "already_blocked", ipb, last_seen, None, None, None, cc, rest)

                                elif m3:
                                    ts_local = parse_local_dt(m3.group("ts"))
                                    ip_str = m3.group("ip")
                                    ipb = ip_address(ip_str).packed
                                    ttl = safe_int(m3.group("ttl"))
                                    remaining = safe_int(m3.group("remaining"))
                                    cc = geoip_country_code(ip_str)
                                    if ts_local:
                                        await db.insert_ntop(ts_local, "expired_removed", ipb, None, ttl, remaining, None, cc, rest)

                                else:
                                    pass
                            except Exception:
                                pass

                    else:
                        await asyncio.sleep(POLL_INTERVAL)
                        try:
                            st2 = os.stat(path)
                            if st2.st_ino != inode:
                                break
                        except FileNotFoundError:
                            break

        except FileNotFoundError:
            await asyncio.sleep(2.0)
        except Exception:
            await asyncio.sleep(1.0)


# ============================================================
# FastAPI app
# ============================================================
app = FastAPI(title="Geo Log Hub", version="1.4.0")

state_store = StateStore(STATE_FILE)
db = DB()
broadcaster = Broadcaster()
latest_lines = deque(maxlen=MAX_LATEST_LINES)


@app.on_event("startup")
async def on_startup():
    await state_store.load()
    await load_country_codes()
    await db.connect()

    for p in [LOG_GEO, LOG_NTOP, LOG_STREAM]:
        asyncio.create_task(tail_file_forever(p, state_store, broadcaster, db, latest_lines))

    async def retention_loop():
        while True:
            try:
                await db.retention_cleanup()
            except Exception:
                pass
            await asyncio.sleep(RETENTION_RUN_EVERY_SEC)

    asyncio.create_task(retention_loop())


# ============================================================
# Health / version
# ============================================================
@app.get("/health")
async def health():
    tz = ZoneInfo("Europe/Berlin")
    utc_now = datetime.now(timezone.utc)
    local_now = utc_now.astimezone(tz)

    return {
        "status": "ok",
        "time_utc": utc_now.isoformat().replace("+00:00", "Z"),
        "time_local": local_now.isoformat(),
        "local_tz": "Europe/Berlin",
        "geoip_enabled": bool(GEOIP_MMDB) and GeoIPReader is not None,
    }


@app.get("/version")
async def version():
    return PlainTextResponse("Geo Log Hub v1.9\n")


# ============================================================
# Logs APIs
# ============================================================
@app.get("/logs/latest")
async def logs_latest(n: int = 200, source: str = "all", q: str = ""):
    n = max(1, min(int(n), MAX_LATEST_LINES))
    source = (source or "all").lower()
    q = (q or "").strip().lower()

    lines = list(latest_lines)
    if source != "all":
        lines = [x for x in lines if x.get("source") == source]
    if q:
        lines = [x for x in lines if q in (x.get("line", "").lower())]
    return {"lines": lines[-n:]}


@app.get("/logs/stream")
async def logs_stream(request: Request):
    q = await broadcaster.register()

    async def event_gen():
        try:
            yield "event: hello\ndata: connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                raw = await q.get()
                yield f"data: {raw}\n\n"
        finally:
            await broadcaster.unregister(q)

    return StreamingResponse(event_gen(), media_type="text/event-stream")


# ============================================================
# GEO APIs (stats + charts + tops + trends + top url by country)
# ============================================================
@app.get("/geo/stats")
async def geo_stats(hours: int = 24):
    hours = clamp_hours(hours)

    total = await db.fetchone(
        "SELECT COUNT(*) AS c FROM geo_blocks WHERE ts_utc >= (UTC_TIMESTAMP() - INTERVAL %s HOUR)",
        (hours,),
    )
    uniq = await db.fetchone(
        "SELECT COUNT(DISTINCT ip) AS c FROM geo_blocks WHERE ts_utc >= (UTC_TIMESTAMP() - INTERVAL %s HOUR)",
        (hours,),
    )
    countries = await db.fetchone(
        "SELECT COUNT(DISTINCT country) AS c FROM geo_blocks WHERE ts_utc >= (UTC_TIMESTAMP() - INTERVAL %s HOUR)",
        (hours,),
    )

    return {
        "window_hours": hours,
        "total": int(total["c"]) if total else 0,
        "unique_ips": int(uniq["c"]) if uniq else 0,
        "countries": int(countries["c"]) if countries else 0,
    }


@app.get("/geo/chart/countries")
async def geo_chart_countries(hours: int = 24, limit: int = 12):
    hours = clamp_hours(hours)
    limit = clamp_limit(limit, 3, 50)

    rows = await db.fetchall(
        f"""
        SELECT country, COUNT(*) AS c
        FROM geo_blocks
        WHERE ts_utc >= (UTC_TIMESTAMP() - INTERVAL %s HOUR)
        GROUP BY country
        ORDER BY c DESC
        LIMIT {limit}
        """,
        (hours,),
    )
    labels = [r["country"] for r in (rows or [])]
    values = [int(r["c"]) for r in (rows or [])]
    return {"labels": labels, "values": values, "window_hours": hours}


@app.get("/geo/chart/ips")
async def geo_chart_ips(hours: int = 24, limit: int = 10):
    hours = clamp_hours(hours)
    limit = clamp_limit(limit, 3, 20)

    rows = await db.fetchall(
        f"""
        SELECT ip, COUNT(*) AS c
        FROM geo_blocks
        WHERE ts_utc >= (UTC_TIMESTAMP() - INTERVAL %s HOUR)
        GROUP BY ip
        ORDER BY c DESC
        LIMIT {limit}
        """,
        (hours,),
    )
    labels = [ip_bytes_to_str(r["ip"]) for r in (rows or [])]
    values = [int(r["c"]) for r in (rows or [])]
    return {"labels": labels, "values": values, "window_hours": hours}


@app.get("/geo/top/urls")
async def geo_top_urls(hours: int = 24, limit: int = 20):
    hours = clamp_hours(hours)
    limit = clamp_limit(limit, 1, 200)

    rows = await db.fetchall(
        f"""
        SELECT url, COUNT(*) AS c
        FROM geo_blocks
        WHERE ts_utc >= (UTC_TIMESTAMP() - INTERVAL %s HOUR)
        GROUP BY url
        ORDER BY c DESC
        LIMIT {limit}
        """,
        (hours,),
    )
    return {"window_hours": hours, "items": [{"url": r["url"], "count": int(r["c"])} for r in (rows or [])]}


@app.get("/geo/top/ips")
async def geo_top_ips(hours: int = 24, limit: int = 15):
    hours = clamp_hours(hours)
    limit = clamp_limit(limit, 1, 200)

    rows = await db.fetchall(
        f"""
        SELECT ip, COUNT(*) AS c
        FROM geo_blocks
        WHERE ts_utc >= (UTC_TIMESTAMP() - INTERVAL %s HOUR)
        GROUP BY ip
        ORDER BY c DESC
        LIMIT {limit}
        """,
        (hours,),
    )
    items = [{"ip": ip_bytes_to_str(r["ip"]), "count": int(r["c"])} for r in (rows or [])]
    return {"window_hours": hours, "items": items}


@app.get("/geo/trend/hourly")
async def geo_trend_hourly(hours: int = 24):
    hours = clamp_hours(hours)

    rows = await db.fetchall(
        """
        SELECT DATE_FORMAT(ts_utc, '%%Y-%%m-%%d %%H:00') AS bucket_utc, COUNT(*) AS c
        FROM geo_blocks
        WHERE ts_utc >= (UTC_TIMESTAMP() - INTERVAL %s HOUR)
        GROUP BY bucket_utc
        ORDER BY bucket_utc ASC
        """,
        (hours,),
    )

    tz = ZoneInfo("Europe/Berlin")
    labels = []
    values = []

    for r in rows or []:
        # bucket_utc z.B. "2026-01-10 10:00"
        dt_utc = datetime.strptime(r["bucket_utc"], "%Y-%m-%d %H:%M")
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
        dt_local = dt_utc.astimezone(tz)

        labels.append(dt_local.strftime("%Y-%m-%d %H:00"))
        values.append(int(r["c"]))

    return {
        "window_hours": hours,
        "labels": labels,
        "values": values,
        "tz": "Europe/Berlin",
    }


@app.get("/geo/top/urls/by-country")
async def geo_top_urls_by_country(hours: int = 24, country: str = "US", limit: int = 20):
    hours = clamp_hours(hours)
    limit = clamp_limit(limit, 1, 200)
    country = (country or "").upper().strip()
    if not re.fullmatch(r"[A-Z]{2}", country):
        country = "US"

    rows = await db.fetchall(
        f"""
        SELECT url, COUNT(*) AS c
        FROM geo_blocks
        WHERE ts_utc >= (UTC_TIMESTAMP() - INTERVAL %s HOUR)
          AND country = %s
        GROUP BY url
        ORDER BY c DESC
        LIMIT {limit}
        """,
        (hours, country),
    )
    return {"window_hours": hours, "country": country, "items": [{"url": r["url"], "count": int(r["c"])} for r in (rows or [])]}


@app.get("/geo/top/countries")
async def geo_top_countries(hours: int = 24, limit: int = 50):
    hours = clamp_hours(hours)
    limit = clamp_limit(limit, 1, 200)

    rows = await db.fetchall(
        f"""
        SELECT country, COUNT(*) AS c
        FROM geo_blocks
        WHERE ts_utc >= (UTC_TIMESTAMP() - INTERVAL %s HOUR)
        GROUP BY country
        ORDER BY c DESC
        LIMIT {limit}
        """,
        (hours,),
    )
    items = []
    for r in (rows or []):
        meta = country_meta(r["country"])
        items.append({**meta, "count": int(r["c"])})
    return {"window_hours": hours, "items": items}


# ============================================================
# NTOP APIs (stats + charts + tops + trends)
# ============================================================
@app.get("/ntop/stats")
async def ntop_stats(hours: int = 24):
    hours = clamp_hours(hours)

    total = await db.fetchone(
        "SELECT COUNT(*) AS c FROM ntop_blacklist_events WHERE ts_local >= (NOW() - INTERVAL %s HOUR)",
        (hours,),
    )
    uniq = await db.fetchone(
        """
        SELECT COUNT(DISTINCT ip) AS c
        FROM ntop_blacklist_events
        WHERE ts_local >= (NOW() - INTERVAL %s HOUR) AND ip IS NOT NULL
        """,
        (hours,),
    )
    new_blocks = await db.fetchone(
        """
        SELECT COUNT(*) AS c
        FROM ntop_blacklist_events
        WHERE ts_local >= (NOW() - INTERVAL %s HOUR) AND action='blocked'
        """,
        (hours,),
    )
    expired = await db.fetchone(
        """
        SELECT COUNT(*) AS c
        FROM ntop_blacklist_events
        WHERE ts_local >= (NOW() - INTERVAL %s HOUR) AND action='expired_removed'
        """,
        (hours,),
    )

    return {
        "window_hours": hours,
        "total_events": int(total["c"]) if total else 0,
        "unique_ips": int(uniq["c"]) if uniq else 0,
        "new_blocks": int(new_blocks["c"]) if new_blocks else 0,
        "expired_removed": int(expired["c"]) if expired else 0,
    }


@app.get("/ntop/chart/actions")
async def ntop_chart_actions(hours: int = 24):
    hours = clamp_hours(hours)
    rows = await db.fetchall(
        """
        SELECT action, COUNT(*) AS c
        FROM ntop_blacklist_events
        WHERE ts_local >= (NOW() - INTERVAL %s HOUR)
        GROUP BY action
        ORDER BY c DESC
        """,
        (hours,),
    )
    labels = [r["action"] for r in (rows or [])]
    values = [int(r["c"]) for r in (rows or [])]
    return {"labels": labels, "values": values, "window_hours": hours}


@app.get("/ntop/chart/countries")
async def ntop_chart_countries(hours: int = 24, limit: int = 10):
    hours = clamp_hours(hours)
    limit = clamp_limit(limit, 3, 50)

    rows = await db.fetchall(
        f"""
        SELECT COALESCE(country,'??') AS country, COUNT(*) AS c
        FROM ntop_blacklist_events
        WHERE ts_local >= (NOW() - INTERVAL %s HOUR)
          AND action IN ('blocked','already_blocked')
        GROUP BY COALESCE(country,'??')
        ORDER BY c DESC
        LIMIT {limit}
        """,
        (hours,),
    )
    labels = [r["country"] for r in (rows or [])]
    values = [int(r["c"]) for r in (rows or [])]
    return {"labels": labels, "values": values, "window_hours": hours}


@app.get("/ntop/chart/ips")
async def ntop_chart_ips(hours: int = 24, limit: int = 10):
    hours = clamp_hours(hours)
    limit = clamp_limit(limit, 3, 20)

    rows = await db.fetchall(
        f"""
        SELECT ip, COUNT(*) AS c
        FROM ntop_blacklist_events
        WHERE ts_local >= (NOW() - INTERVAL %s HOUR)
          AND ip IS NOT NULL
          AND action IN ('blocked','already_blocked')
        GROUP BY ip
        ORDER BY c DESC
        LIMIT {limit}
        """,
        (hours,),
    )
    labels = [ip_bytes_to_str(r["ip"]) for r in (rows or [])]
    values = [int(r["c"]) for r in (rows or [])]
    return {"labels": labels, "values": values, "window_hours": hours}


@app.get("/ntop/top/ips")
async def ntop_top_ips(hours: int = 24, limit: int = 15):
    hours = clamp_hours(hours)
    limit = clamp_limit(limit, 1, 200)

    rows = await db.fetchall(
        f"""
        SELECT ip, COUNT(*) AS c
        FROM ntop_blacklist_events
        WHERE ts_local >= (NOW() - INTERVAL %s HOUR)
          AND ip IS NOT NULL
          AND action IN ('blocked','already_blocked')
        GROUP BY ip
        ORDER BY c DESC
        LIMIT {limit}
        """,
        (hours,),
    )
    items = []
    for r in (rows or []):
        ipb = r.get("ip")
        items.append({"ip": ip_bytes_to_str(ipb) if ipb else None, "count": int(r.get("c", 0))})
    return {"window_hours": hours, "items": items}


@app.get("/ntop/top/countries")
async def ntop_top_countries(hours: int = 24, limit: int = 15):
    hours = clamp_hours(hours)
    limit = clamp_limit(limit, 1, 200)

    rows = await db.fetchall(
        f"""
        SELECT COALESCE(country,'??') AS country, COUNT(*) AS c
        FROM ntop_blacklist_events
        WHERE ts_local >= (NOW() - INTERVAL %s HOUR)
          AND action IN ('blocked','already_blocked')
        GROUP BY COALESCE(country,'??')
        ORDER BY c DESC
        LIMIT {limit}
        """,
        (hours,),
    )

    items = []
    for r in (rows or []):
        cc = (r["country"] or "??")
        meta = country_meta(cc) if cc != "??" else {"country":"??","country_name":"Unbekannt","flag":""}
        items.append({**meta, "count": int(r["c"])})
    return {"window_hours": hours, "items": items}

@app.get("/meta/countries")
async def meta_countries():
    # Sortiert nach Code
    items = [ISO2_META[k] for k in sorted(ISO2_META.keys())]
    return {"count": len(items), "items": items}

@app.get("/ntop/trend/hourly")
async def ntop_trend_hourly(hours: int = 24):
    hours = clamp_hours(hours)

    rows = await db.fetchall(
        """
        SELECT DATE_FORMAT(ts_local, '%%Y-%%m-%%d %%H:00') AS bucket_local, COUNT(*) AS c
        FROM ntop_blacklist_events
        WHERE ts_local >= (NOW() - INTERVAL %s HOUR)
          AND action IN ('blocked','already_blocked')
        GROUP BY bucket_local
        ORDER BY bucket_local ASC
        """,
        (hours,),
    )

    # NTOP ts_local ist bereits lokale Zeit → kein TZ-Shift nötig
    labels = [r["bucket_local"] for r in (rows or [])]
    values = [int(r["c"]) for r in (rows or [])]

    return {
        "window_hours": hours,
        "labels": labels,
        "values": values,
        "tz": "Europe/Berlin",
    }



# ============================================================
# Web UI
# ============================================================
@app.get("/")
async def ui():
    html = """<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Geo Log Hub</title>
<style>
  :root{
    --bg:#0b0f14; --card:#0f172a; --card2:#111827; --line:#233047;
    --txt:#d6deeb; --muted:#93a4bd; --acc:#93c5fd;
  }
  body{margin:0;background:var(--bg);color:var(--txt);font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif}
  header{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:12px 16px;background:var(--card2);border-bottom:1px solid var(--line)}
  header b{letter-spacing:.2px}
  main{padding:12px 16px}
  .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:12px}
  .card{background:var(--card);border:1px solid #1f2a44;border-radius:14px;padding:12px}
  .span6{grid-column:span 6}
  .span4{grid-column:span 4}
  .span8{grid-column:span 8}
  .span12{grid-column:span 12}
  @media (max-width: 980px){
    .span6,.span4,.span8{grid-column:span 12}
  }
  .kpi{display:flex;gap:8px;align-items:baseline}
  .kpi .v{font-size:26px;font-weight:700}
  .kpi .l{color:var(--muted);font-size:12px}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  input,select,button{background:#0b1220;color:var(--txt);border:1px solid #2a3a5a;border-radius:10px;padding:8px 10px}
  button{cursor:pointer}
  button:hover{border-color:#3d5a93}
  a{color:var(--acc);text-decoration:none}
  a:hover{text-decoration:underline}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px}
  #log{height:48vh;overflow:auto;white-space:pre-wrap}
  .pill{padding:2px 8px;border:1px solid #2a3a5a;border-radius:999px;color:var(--muted);font-size:12px}
  .muted{color:var(--muted)}
  .table{width:100%;border-collapse:collapse}
  .table th,.table td{border-bottom:1px solid #1f2a44;padding:8px 6px;text-align:left;font-size:13px}
  .tight td{padding:6px 6px}
  .right{text-align:right}
  .legend{ margin-top:10px; }
.legend ul{
  list-style:none; padding:0; margin:0;
  display:flex; flex-wrap:wrap; gap:8px 10px;
  justify-content:center;
}
.legend li{
  display:flex; align-items:center; gap:8px;
  padding:4px 8px;
  border:1px solid #2a3a5a;
  border-radius:999px;
  color: var(--txt);
  cursor:pointer;
  user-select:none;
  font-size:12px;
}
.legend li:hover{ border-color:#3d5a93; }
.legend .box{
  width:10px; height:10px; border-radius:3px;
  border:1px solid rgba(255,255,255,0.25);
}
.legend .muted{ color: var(--muted); }
</style>
</head>
<body>
<header>
  <b>Geo Log Hub</b>
  <span class="pill">Live Logs + Stats</span>
  <span class="muted">•</span>
  <a href="/health" target="_blank">health</a>
  <a href="/version" target="_blank">version</a>
</header>

<main class="grid">
  <div class="card span12">
    <div class="row" style="justify-content:space-between">
      <div class="row">
        <b>Zeitraum</b>
        <select id="hours" onchange="reloadAll()">
          <option value="1">1h</option>
          <option value="6">6h</option>
          <option value="24" selected>24h</option>
          <option value="168">7d</option>
          <option value="720">30d</option>
        </select>
        <span class="pill" id="conn">connecting…</span>
      </div>
      <div class="row">
        <button onclick="reloadAll()">Reload</button>
      </div>
    </div>
  </div>

  <!-- GEO KPI + PIE -->
  <div class="card span4">
    <div class="row" style="justify-content:space-between">
      <b>GEO</b>
      <select id="geoMode" onchange="loadGeo()">
        <option value="countries" selected>Länder</option>
        <option value="ips">IPs</option>
      </select>
    </div>

    <div class="kpi" style="margin-top:8px"><div class="v" id="geoTotal">-</div><div class="l">geblockt</div></div>
    <div class="kpi" style="margin-top:6px"><div class="v" id="geoUniq">-</div><div class="l">Unique IPs</div></div>
    <div class="kpi" style="margin-top:6px"><div class="v" id="geoCountries">-</div><div class="l">Länder</div></div>
    <div class="muted" style="margin-top:10px">Pie je nach Modus.</div>
    <canvas id="geoPie" style="margin-top:10px"></canvas>
    <div id="geoLegend" class="legend"></div>
  </div>

  <!-- NTOP KPI + PIE -->
  <div class="card span4">
    <div class="row" style="justify-content:space-between">
      <b>NTOP</b>
      <select id="ntopMode" onchange="loadNtop()">
        <option value="actions" selected>Actions</option>
        <option value="countries">Länder</option>
        <option value="ips">IPs</option>
      </select>
    </div>

    <div class="kpi" style="margin-top:8px"><div class="v" id="ntopNew">-</div><div class="l">neue Blocks</div></div>
    <div class="kpi" style="margin-top:6px"><div class="v" id="ntopTotal">-</div><div class="l">Events</div></div>
    <div class="kpi" style="margin-top:6px"><div class="v" id="ntopUniq">-</div><div class="l">Unique IPs</div></div>
    <div class="muted" style="margin-top:10px">Pie je nach Modus.</div>
    <canvas id="ntopPie" style="margin-top:10px"></canvas>
    <div id="ntopLegend" class="legend"></div>
  </div>

  <!-- NTOP Top IPs -->
  <div class="card span4">
    <div class="row" style="justify-content:space-between">
      <b>NTOP Top IPs</b>
      <button onclick="loadNtopTopIps()">Reload</button>
    </div>
    <table class="table tight" style="margin-top:8px">
      <thead><tr><th>IP</th><th class="right">Count</th></tr></thead>
      <tbody id="ntopTopIps"><tr><td class="muted" colspan="2">loading…</td></tr></tbody>
    </table>
  </div>

  <!-- Trends -->
  <div class="card span6">
    <div class="row" style="justify-content:space-between">
      <b>Trend GEO (pro Stunde)</b>
      <button onclick="loadGeoTrend()">Reload</button>
    </div>
    <canvas id="geoTrend" style="margin-top:10px"></canvas>
  </div>

  <div class="card span6">
    <div class="row" style="justify-content:space-between">
      <b>Trend NTOP (pro Stunde)</b>
      <button onclick="loadNtopTrend()">Reload</button>
    </div>
    <canvas id="ntopTrend" style="margin-top:10px"></canvas>
  </div>

  <!-- GEO Top URLs -->
  <div class="card span6">
    <div class="row" style="justify-content:space-between">
      <b>GEO Top URLs</b>
      <button onclick="loadGeoTopUrls()">Reload</button>
    </div>
    <table class="table tight" style="margin-top:8px">
      <thead><tr><th>URL</th><th class="right">Count</th></tr></thead>
      <tbody id="geoTopUrls"><tr><td class="muted" colspan="2">loading…</td></tr></tbody>
    </table>
  </div>

  <!-- GEO Top IPs -->
  <div class="card span6">
    <div class="row" style="justify-content:space-between">
      <b>GEO Top IPs</b>
      <button onclick="loadGeoTopIps()">Reload</button>
    </div>
    <table class="table tight" style="margin-top:8px">
      <thead><tr><th>IP</th><th class="right">Count</th></tr></thead>
      <tbody id="geoTopIps"><tr><td class="muted" colspan="2">loading…</td></tr></tbody>
    </table>
  </div>

  <!-- NTOP Top Countries -->
  <div class="card span6">
    <div class="row" style="justify-content:space-between">
      <b>NTOP Top Länder</b>
      <button onclick="loadNtopTopCountries()">Reload</button>
    </div>
    <div class="muted" style="margin-top:6px">Kommt aus GeoIP (wenn GEOIP_MMDB gesetzt). Sonst meist "??".</div>
    <table class="table tight" style="margin-top:8px">
      <thead><tr><th>Land</th><th class="right">Count</th></tr></thead>
      <tbody id="ntopTopCountries"><tr><td class="muted" colspan="2">loading…</td></tr></tbody>
    </table>
  </div>

  <!-- GEO Top URL by Country -->
  <div class="card span6">
    <div class="row" style="justify-content:space-between">
      <div class="row">
        <b>GEO Top URLs pro Land</b>
        <select id="geoCountry" onchange="loadGeoTopUrlsByCountry()"></select>
      </div>
      <button onclick="loadGeoTopUrlsByCountry()">Reload</button>
    </div>
    <div class="muted" style="margin-top:6px">Land-Auswahl kommt aus den Top Ländern im Zeitraum.</div>
    <table class="table tight" style="margin-top:8px">
      <thead><tr><th>URL</th><th class="right">Count</th></tr></thead>
      <tbody id="geoTopUrlsByCountry"><tr><td class="muted" colspan="2">loading…</td></tr></tbody>
    </table>
  </div>

  <!-- Logs -->
  <div class="card span12">
    <div class="row" style="justify-content:space-between">
      <div class="row">
        <b>Logs</b>
      </div>
      <div class="row">
        <select id="source">
          <option value="all">Alle</option>
          <option value="geo">GEO</option>
          <option value="ntop">NTOP</option>
          <option value="stream">STREAM</option>
        </select>
        <input id="filter" placeholder="Filter (Text enthält…)" size="22" />
        <button onclick="clearLog()">Clear</button>
        <button onclick="togglePause()" id="pauseBtn">Pause</button>
        <button onclick="loadLatest()">Latest</button>
      </div>
    </div>
    <div id="log" class="mono" style="margin-top:10px"></div>
  </div>

</main>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script>
let paused=false;
let es=null;
let geoPie=null;
let ntopPie=null;
let geoTrend=null;
let ntopTrend=null;

let COUNTRY = {}; // ISO2 -> {country,country_name,flag}

const htmlLegendPlugin = {
  id: 'htmlLegend',
  afterUpdate(chart, args, opts) {
    const container = document.getElementById(opts.containerID);
    if (!container) return;

    container.innerHTML = '';
    const ul = document.createElement('ul');

    const labels = chart.data.labels || [];
    const meta = chart.getDatasetMeta(0);
    const ctrl = meta?.controller;

    labels.forEach((raw, i) => {
      const li = document.createElement('li');

      const visible = chart.getDataVisibility(i);
      li.style.opacity = visible ? '1' : '0.45';

      // Farbe pro Slice zuverlässig holen
      let bg = '#3b82f6'; // fallback
      try {
        const style = ctrl?.getStyle(i);
        if (style?.backgroundColor) bg = style.backgroundColor;
      } catch(_) {}

      const box = document.createElement('span');
      box.className = 'box';
      box.style.backgroundColor = bg;

      let text = String(raw ?? '');
      let title = text;

      if (opts.decorateCountries && typeof raw === 'string' && raw.length === 2) {
        const lab = countryLabel(raw);
        text = lab.text || raw;     // "🇩🇪 DE"
        title = lab.title || raw;   // "Deutschland (DE)"
      }

      const label = document.createElement('span');
      label.textContent = text;
      li.title = title;

      // Click = ein/ausblenden
      li.onclick = () => {
        chart.toggleDataVisibility(i);
        chart.update();
      };

      // Mouseover = Tooltip + Highlight (nice!)
      li.onmouseenter = () => {
        chart.setActiveElements([{ datasetIndex: 0, index: i }]);
        chart.tooltip?.update();
        chart.draw();
      };
      li.onmouseleave = () => {
        chart.setActiveElements([]);
        chart.tooltip?.update();
        chart.draw();
      };

      li.appendChild(box);
      li.appendChild(label);
      ul.appendChild(li);
    });

    container.appendChild(ul);
  }
};

async function loadCountryMeta(){
  try{
    const r = await fetch('/meta/countries');
    const j = await r.json();
    const map = {};
    (j.items || []).forEach(it => { map[it.country] = it; });
    COUNTRY = map;
  }catch(e){
    COUNTRY = {};
  }
}

function countryLabel(code){
  code = (code || '').toUpperCase();
  if(code === '??' || !code) return { code:'??', text: '??', title: 'Unbekannt', flag: '' };

  const it = COUNTRY[code];
  if(!it) return { code, text: code, title: code, flag: '' };

  const flag = it.flag || '';
  const title = `${it.country_name} (${it.country})`;
  const text = `${flag ? flag+' ' : ''}${it.country}`;   // <- FLAG + ISO2
  return { code: it.country, text, title, flag };
}

const logEl=document.getElementById('log');
const pauseBtn=document.getElementById('pauseBtn');
const connEl=document.getElementById('conn');

function getHours(){
  return parseInt(document.getElementById('hours').value || '24', 10);
}
function geoMode(){
  return document.getElementById('geoMode').value || 'countries';
}
function ntopMode(){
  return document.getElementById('ntopMode').value || 'actions';
}

function wantSource(){
  return document.getElementById('source').value;
}
function wantFilter(){
  return (document.getElementById('filter').value||'').toLowerCase().trim();
}

function shouldShow(source, line){
  const s = wantSource();
  if(s !== 'all' && source !== s) return false;
  const q = wantFilter();
  if(q && !line.toLowerCase().includes(q)) return false;
  return true;
}

function addLine(source, line){
  if(paused) return;
  if(!shouldShow(source, line)) return;

  const atBottom = (logEl.scrollTop + logEl.clientHeight) >= (logEl.scrollHeight - 25);
  logEl.textContent += line + "\\n";
  if(atBottom) logEl.scrollTop = logEl.scrollHeight;
}

function clearLog(){ logEl.textContent=""; }

function togglePause(){
  paused=!paused;
  pauseBtn.textContent = paused ? "Resume" : "Pause";
}

async function loadLatest(){
  const s = wantSource();
  const q = encodeURIComponent(wantFilter());
  const url = `/logs/latest?n=250&source=${encodeURIComponent(s)}&q=${q}`;
  const r = await fetch(url);
  const j = await r.json();
  clearLog();
  (j.lines||[]).forEach(x => addLine(x.source, x.line));
}

function connect(){
  connEl.textContent = 'connecting…';
  es = new EventSource('/logs/stream');
  es.onopen = ()=> { connEl.textContent='live'; };
  es.onmessage = (e)=>{
    try{
      const obj = JSON.parse(e.data);
      addLine(obj.source, obj.line);
    }catch(_){}
  };
  es.onerror = ()=>{
    connEl.textContent='reconnecting…';
    try{ es.close(); }catch(_){}
    setTimeout(connect, 1500);
  };
}

function makePie(canvasId, labels, values, decorateCountries=false){
  const el = document.getElementById(canvasId);
  if(!el) return null;

  const legendContainerID = (canvasId === 'geoPie') ? 'geoLegend' : 'ntopLegend';

  return new Chart(el, {
    type: 'pie',
    data: { labels, datasets: [{ data: values }] },
    plugins: [htmlLegendPlugin],
    options: {
      plugins: {
        // Canvas-Legend AUS (die hat dir "undefined" reingeschossen)
        legend: { display: false },

        // Unsere HTML-Legend
        htmlLegend: {
          containerID: legendContainerID,
          decorateCountries: decorateCountries
        },

        // Tooltips bleiben (für Pie hover)
        tooltip: {
          callbacks: {
            title: (items) => {
              const raw = items?.[0]?.label ?? '';
              if(decorateCountries && typeof raw === 'string' && raw.length === 2){
                return countryLabel(raw).title || raw;
              }
              return String(raw ?? '');
            },
            label: (ctx) => {
              const raw = ctx.label ?? '';
              const v = ctx.parsed ?? 0;

              if(decorateCountries && typeof raw === 'string' && raw.length === 2){
                const lab = countryLabel(raw);
                return `${lab.text || raw}: ${v}`;
              }
              return `${String(raw)}: ${v}`;
            }
          }
        }
      }
    }
  });
}


function makeLine(canvasId, labels, values){
  const ctx = document.getElementById(canvasId);
  return new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        data: values,
        tension: 0.25,
        fill: false
      }]
    },
    options: {
      plugins: { legend: { display:false } },
      scales: {
        x: { ticks: { color:'#93a4bd' }, grid: { color:'rgba(35,48,71,0.4)' } },
        y: { ticks: { color:'#93a4bd' }, grid: { color:'rgba(35,48,71,0.4)' } }
      }
    }
  });
}

function escapeHtml(s){
  return String(s)
    .replaceAll('&','&amp;')
    .replaceAll('<','&lt;')
    .replaceAll('>','&gt;')
    .replaceAll('"','&quot;')
    .replaceAll("'","&#039;");
}

async function loadGeo(){
  const h = getHours();

  const r = await fetch(`/geo/stats?hours=${h}`);
  const j = await r.json();
  document.getElementById('geoTotal').textContent = j.total ?? '-';
  document.getElementById('geoUniq').textContent  = j.unique_ips ?? '-';
  document.getElementById('geoCountries').textContent  = j.countries ?? '-';

  const mode = geoMode();
  const decorate = (mode === 'countries');

  let chartUrl = `/geo/chart/countries?hours=${h}&limit=10`;
  if(mode === 'ips') chartUrl = `/geo/chart/ips?hours=${h}&limit=10`;

  const c = await fetch(chartUrl);
  const cj = await c.json();

  if(geoPie) geoPie.destroy();
  geoPie = makePie('geoPie', cj.labels || [], cj.values || [], decorate);
}

async function loadNtop(){
  const h = getHours();

  const r = await fetch(`/ntop/stats?hours=${h}`);
  const j = await r.json();
  document.getElementById('ntopNew').textContent   = j.new_blocks ?? '-';
  document.getElementById('ntopTotal').textContent = j.total_events ?? '-';
  document.getElementById('ntopUniq').textContent  = j.unique_ips ?? '-';

  const mode = ntopMode();
  const decorate = (mode === 'countries');

  let chartUrl = `/ntop/chart/actions?hours=${h}`;
  if(mode === 'countries') chartUrl = `/ntop/chart/countries?hours=${h}&limit=10`;
  if(mode === 'ips')       chartUrl = `/ntop/chart/ips?hours=${h}&limit=10`;

  const c = await fetch(chartUrl);
  const cj = await c.json();

  if(ntopPie) ntopPie.destroy();
  ntopPie = makePie('ntopPie', cj.labels || [], cj.values || [], decorate);
}

async function loadGeoTopUrls(){
  const h = getHours();
  const r = await fetch(`/geo/top/urls?hours=${h}&limit=15`);
  const j = await r.json();
  const tb = document.getElementById('geoTopUrls');
  const items = j.items || [];
  tb.innerHTML = items.length ? '' : '<tr><td class="muted" colspan="2">keine Daten</td></tr>';
  items.forEach(it=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="mono">${escapeHtml(it.url || '-')}</td><td class="right">${it.count || 0}</td>`;
    tb.appendChild(tr);
  });
}

async function loadGeoTopIps(){
  const h = getHours();
  const r = await fetch(`/geo/top/ips?hours=${h}&limit=15`);
  const j = await r.json();
  const tb = document.getElementById('geoTopIps');
  const items = j.items || [];
  tb.innerHTML = items.length ? '' : '<tr><td class="muted" colspan="2">keine Daten</td></tr>';
  items.forEach(it=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="mono">${escapeHtml(it.ip || '-')}</td><td class="right">${it.count || 0}</td>`;
    tb.appendChild(tr);
  });
}

async function loadNtopTopIps(){
  const h = getHours();
  const r = await fetch(`/ntop/top/ips?hours=${h}&limit=15`);
  const j = await r.json();
  const tb = document.getElementById('ntopTopIps');
  const items = j.items || [];
  tb.innerHTML = items.length ? '' : '<tr><td class="muted" colspan="2">keine Daten</td></tr>';
  items.forEach(it=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="mono">${escapeHtml(it.ip || '-')}</td><td class="right">${it.count || 0}</td>`;
    tb.appendChild(tr);
  });
}

async function loadNtopTopCountries(){
  const h = getHours();
  const r = await fetch(`/ntop/top/countries?hours=${h}&limit=15`);
  const j = await r.json();
  const tb = document.getElementById('ntopTopCountries');
  const items = j.items || [];
  tb.innerHTML = items.length ? '' : '<tr><td class="muted" colspan="2">keine Daten</td></tr>';
  items.forEach(it=>{
    const tr = document.createElement('tr');
    const cc = it.country || '??';
    const lab = countryLabel(cc);
    tr.innerHTML = `
    <td class="mono"><span title="${escapeHtml(lab.title)}">${escapeHtml(lab.text)}</span></td>
    <td class="right">${it.count || 0}</td>
    `;
    tb.appendChild(tr);
  });
}

async function loadGeoTrend(){
  const h = getHours();
  const r = await fetch(`/geo/trend/hourly?hours=${h}`);
  const j = await r.json();
  if(geoTrend) geoTrend.destroy();
  geoTrend = makeLine('geoTrend', j.labels || [], j.values || []);
}

async function loadNtopTrend(){
  const h = getHours();
  const r = await fetch(`/ntop/trend/hourly?hours=${h}`);
  const j = await r.json();
  if(ntopTrend) ntopTrend.destroy();
  ntopTrend = makeLine('ntopTrend', j.labels || [], j.values || []);
}

async function loadGeoCountriesDropdown(){
  const h = getHours();
  const r = await fetch(`/geo/top/countries?hours=${h}&limit=50`);
  const j = await r.json();
  const sel = document.getElementById('geoCountry');
  const items = j.items || [];
  const current = sel.value || (items[0]?.country ?? 'US');

  sel.innerHTML = '';
  if(items.length === 0){
    const opt = document.createElement('option');
    opt.value = 'US';
    opt.textContent = 'US';
    sel.appendChild(opt);
    return;
  }
  items.forEach(it=>{
    const opt = document.createElement('option');
    opt.value = it.country;
    const lab = countryLabel(it.country);
    opt.textContent = `${lab.flag ? lab.flag+' ' : ''}${it.country} (${it.count})`;
    opt.title = lab.title;
    sel.appendChild(opt);
  });

  // restore selection if possible
  const exists = Array.from(sel.options).some(o => o.value === current);
  sel.value = exists ? current : items[0].country;
}

async function loadGeoTopUrlsByCountry(){
  const h = getHours();
  const country = (document.getElementById('geoCountry').value || 'US');
  const r = await fetch(`/geo/top/urls/by-country?hours=${h}&country=${encodeURIComponent(country)}&limit=15`);
  const j = await r.json();
  const tb = document.getElementById('geoTopUrlsByCountry');
  const items = j.items || [];
  tb.innerHTML = items.length ? '' : '<tr><td class="muted" colspan="2">keine Daten</td></tr>';
  items.forEach(it=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="mono">${escapeHtml(it.url || '-')}</td><td class="right">${it.count || 0}</td>`;
    tb.appendChild(tr);
  });
}

async function reloadAll(){
  await Promise.allSettled([
    loadGeo(),
    loadNtop(),
    loadGeoTopUrls(),
    loadGeoTopIps(),
    loadNtopTopIps(),
    loadNtopTopCountries(),
    loadGeoTrend(),
    loadNtopTrend(),
    loadGeoCountriesDropdown(),
  ]);
  await loadGeoTopUrlsByCountry();
}

// initial load
async function init(){
  try{
    await loadCountryMeta();
    await reloadAll();
    await loadLatest();
    connect();
    setInterval(()=>{ reloadAll(); }, 60_000);
  }catch(e){
    console.error("init failed", e);
    connEl.textContent = "init failed";
  }
}

init();
</script>
</body>
</html>"""
    return StreamingResponse(iter([html]), media_type="text/html; charset=utf-8")
