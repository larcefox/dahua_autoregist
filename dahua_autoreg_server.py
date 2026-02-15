import json
import sqlite3
import time
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse

DB_PATH = "devices.db"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8000
BUILD_TAG = "2026-02-15-autoregist-compact"
KEEP_ALIVE_INTERVAL_SEC = 30
KEEP_ALIVE_TIMEOUT_SEC = 90
CONNECT_PLAIN_OK = True  # если камера упёртая, отдаем "OK" текстом на connect

app = FastAPI(title="Dahua AutoRegister Server (tolerant)")


# ---------- DB ----------
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            ip TEXT,
            path TEXT,
            method TEXT,
            serial TEXT,
            mac TEXT,
            model TEXT,
            device_id TEXT,
            dev_class TEXT,
            server_ip TEXT,
            payload_json TEXT,
            raw_body TEXT
        )
        """
    )
    # Safe migrations for existing DB
    columns = [r["name"] for r in conn.execute("PRAGMA table_info(devices)").fetchall()]
    if "device_id" not in columns:
        conn.execute("ALTER TABLE devices ADD COLUMN device_id TEXT")
    if "dev_class" not in columns:
        conn.execute("ALTER TABLE devices ADD COLUMN dev_class TEXT")
    if "server_ip" not in columns:
        conn.execute("ALTER TABLE devices ADD COLUMN server_ip TEXT")
    conn.commit()
    conn.close()


def pick_device_identifiers(payload: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    serial = (
        payload.get("sn")
        or payload.get("serial")
        or payload.get("Serial")
        or payload.get("deviceSn")
        or payload.get("deviceSN")
        or payload.get("DeviceSN")
        or None
    )
    device_id = payload.get("DeviceID") or payload.get("deviceId") or payload.get("device_id") or None
    if not serial and device_id:
        # Many Dahua AutoRegist payloads use DeviceID instead of serial.
        serial = str(device_id)
    dev_class = payload.get("DevClass") or payload.get("devClass") or payload.get("deviceClass") or None
    server_ip = payload.get("ServerIP") or payload.get("serverIP") or payload.get("serverIp") or None
    return serial, device_id, dev_class, server_ip


def upsert_device(ip: str, path: str, method: str, payload: Dict[str, Any], raw_body: str) -> Optional[str]:
    # Пытаемся вытащить идентификаторы из того, что прислала камера
    serial, device_id, dev_class, server_ip = pick_device_identifiers(payload)
    mac = payload.get("mac") or payload.get("MAC") or payload.get("deviceMac") or None
    model = payload.get("model") or payload.get("Model") or payload.get("deviceModel") or None

    now = int(time.time())
    conn = db()

    # Если serial есть — используем как ключ
    if serial:
        row = conn.execute("SELECT id FROM devices WHERE serial = ?", (serial,)).fetchone()
        if row:
            conn.execute(
                """
                UPDATE devices
                SET last_seen=?, ip=?, path=?, method=?, mac=COALESCE(?, mac),
                    model=COALESCE(?, model), device_id=COALESCE(?, device_id),
                    dev_class=COALESCE(?, dev_class), server_ip=COALESCE(?, server_ip),
                    payload_json=?, raw_body=?
                WHERE id=?
                """,
                (
                    now,
                    ip,
                    path,
                    method,
                    mac,
                    model,
                    str(device_id) if device_id is not None else None,
                    str(dev_class) if dev_class is not None else None,
                    str(server_ip) if server_ip is not None else None,
                    json.dumps(payload, ensure_ascii=False),
                    raw_body,
                    row["id"],
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO devices (first_seen, last_seen, ip, path, method, serial, mac, model, device_id, dev_class, server_ip, payload_json, raw_body)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    now,
                    ip,
                    path,
                    method,
                    serial,
                    mac,
                    model,
                    str(device_id) if device_id is not None else None,
                    str(dev_class) if dev_class is not None else None,
                    str(server_ip) if server_ip is not None else None,
                    json.dumps(payload, ensure_ascii=False),
                    raw_body,
                ),
            )
    else:
        # Если serial нет — просто добавляем запись (можно улучшить, если нужно)
        conn.execute(
            """
            INSERT INTO devices (first_seen, last_seen, ip, path, method, serial, mac, model, device_id, dev_class, server_ip, payload_json, raw_body)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                now,
                ip,
                path,
                method,
                None,
                mac,
                model,
                str(device_id) if device_id is not None else None,
                str(dev_class) if dev_class is not None else None,
                str(server_ip) if server_ip is not None else None,
                json.dumps(payload, ensure_ascii=False),
                raw_body,
            ),
        )

    conn.commit()
    conn.close()
    return serial


# ---------- parsing ----------
async def parse_payload(request: Request) -> Dict[str, Any]:
    """
    Пытаемся распарсить тело:
    - JSON
    - form-urlencoded / multipart
    - иначе возвращаем {"raw": "..."} (текст)
    """
    content_type = (request.headers.get("content-type") or "").lower()
    raw_bytes = await request.body()
    raw_text = raw_bytes.decode("utf-8", errors="replace")

    # JSON
    if "application/json" in content_type:
        try:
            return json.loads(raw_text) if raw_text else {}
        except Exception:
            return {"raw": raw_text}

    # Form
    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        try:
            form = await request.form()
            return dict(form)
        except Exception:
            return {"raw": raw_text}

    # Некоторые камеры присылают text/plain или вообще без типа
    # Иногда там JSON без правильного content-type — попробуем распарсить
    stripped = raw_text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            return json.loads(stripped)
        except Exception:
            pass

    return {"raw": raw_text}


def success_response(extra: Optional[Dict[str, Any]] = None) -> JSONResponse:
    """
    Универсальный "успешный" ответ.
    Dahua в разных прошивках может ожидать разные поля,
    поэтому возвращаем несколько распространённых вариантов.
    """
    base = {"result": True, "success": True, "code": 0, "msg": "OK", "message": "OK"}
    if extra:
        base.update(extra)
    response = JSONResponse(base, status_code=200)
    response.headers["Cache-Control"] = "no-store"
    return response


def autoregist_response(action: str, serial: Optional[str], request: Request, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Возвращает более "богатый" ответ для частых подпутей AutoRegist.
    Так камера получает явные интервалы keepalive и подтверждение регистрации.
    """
    now = int(time.time())
    device_id = payload.get("DeviceID") or payload.get("deviceId") or payload.get("device_id")
    dev_class = payload.get("DevClass") or payload.get("devClass")
    server_ip = payload.get("ServerIP") or request.url.hostname or LISTEN_HOST
    server_port = request.url.port or LISTEN_PORT
    params = {
        "KeepAliveInterval": KEEP_ALIVE_INTERVAL_SEC,
        "Interval": KEEP_ALIVE_INTERVAL_SEC,
        "keepAliveInterval": KEEP_ALIVE_INTERVAL_SEC,
        "KeepAliveTime": KEEP_ALIVE_INTERVAL_SEC,
        "TimeOut": KEEP_ALIVE_TIMEOUT_SEC,
        "Timeout": KEEP_ALIVE_TIMEOUT_SEC,
        "ServerTime": now,
        "ServerIP": server_ip,
        "ServerPort": server_port,
        "ip": server_ip,
        "port": server_port,
    }
    if serial:
        params["Serial"] = serial
    if device_id:
        params["DeviceID"] = device_id
        params["deviceId"] = device_id
    if dev_class:
        params["DevClass"] = dev_class

    if action in {"connect", "register", "regist"}:
        # Отдаем и плоские поля, и params — разные прошивки смотрят по-разному.
        payload_dict = {
            "result": True,
            "success": True,
            "code": 0,
            "msg": "OK",
            "message": "OK",
            "status": 0,
            "ip": server_ip,
            "port": server_port,
            "KeepAliveInterval": KEEP_ALIVE_INTERVAL_SEC,
            "TimeOut": KEEP_ALIVE_TIMEOUT_SEC,
            "event": "connect-ack",
            "keepAliveSec": KEEP_ALIVE_INTERVAL_SEC,
            "timeoutSec": KEEP_ALIVE_TIMEOUT_SEC,
            "Serial": serial,
            "DeviceID": device_id,
            "deviceId": device_id,
            "DevClass": dev_class,
            "params": params,
            "build": BUILD_TAG,
        }
        # Некоторые прошивки ждут просто "OK" без JSON — отдадим текстом.
        if CONNECT_PLAIN_OK:
            return PlainTextResponse("OK", status_code=200, headers={"Cache-Control": "no-store"})
        return payload_dict
    if action in {"keepAlive", "keepalive", "alive", "heartbeat"}:
        return {"result": True, "success": True, "code": 0, "msg": "OK", "message": "OK", "ServerTime": now, "build": BUILD_TAG}
    if action in {"disconnect", "unregister"}:
        return {"result": True, "success": True, "code": 0, "msg": "OK", "message": "OK", "build": BUILD_TAG}
    return {"result": True, "success": True, "code": 0, "msg": "OK", "message": "OK", "build": BUILD_TAG}


@app.on_event("startup")
def on_startup() -> None:
    init_db()


# ---------- endpoints ----------
@app.get("/", response_class=HTMLResponse)
def index():
    conn = db()
    rows = conn.execute(
        "SELECT id, first_seen, last_seen, ip, serial, mac, model, path, method FROM devices ORDER BY last_seen DESC"
    ).fetchall()
    conn.close()

    def ts(t: int) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))

    html = [
        "<html><head><meta charset='utf-8'><title>Dahua AutoRegister</title></head><body>",
        "<h2>Registered devices</h2>",
        "<table border='1' cellpadding='6' cellspacing='0'>",
        "<tr><th>ID</th><th>First seen</th><th>Last seen</th><th>IP</th><th>Serial</th><th>MAC</th><th>Model</th><th>Last path</th><th>Method</th></tr>",
    ]
    for r in rows:
        html.append(
            "<tr>"
            f"<td>{r['id']}</td>"
            f"<td>{ts(r['first_seen'])}</td>"
            f"<td>{ts(r['last_seen'])}</td>"
            f"<td>{r['ip'] or ''}</td>"
            f"<td>{r['serial'] or ''}</td>"
            f"<td>{r['mac'] or ''}</td>"
            f"<td>{r['model'] or ''}</td>"
            f"<td>{r['path'] or ''}</td>"
            f"<td>{r['method'] or ''}</td>"
            "</tr>"
        )
    html += ["</table>", "<p>Details: <code>/device/{id}</code></p>", "</body></html>"]
    return HTMLResponse("\n".join(html))


@app.get("/device/{device_id}", response_class=HTMLResponse)
def device_details(device_id: int):
    conn = db()
    r = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    conn.close()
    if not r:
        return HTMLResponse("<h3>Not found</h3>", status_code=404)

    html = [
        "<html><head><meta charset='utf-8'><title>Device</title></head><body>",
        f"<h2>Device #{device_id}</h2>",
        "<pre>",
    ]
    for k in r.keys():
        html.append(f"{k}: {r[k]}")
    html += ["</pre>", "<a href='/'>Back</a>", "</body></html>"]
    return HTMLResponse("\n".join(html))


# Главный “толерантный” обработчик для всех путей AutoRegist
@app.api_route("/cgi-bin/api/autoRegist/{rest:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def autoreg_any(rest: str, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    path = f"/cgi-bin/api/autoRegist/{rest}"
    method = request.method

    payload = await parse_payload(request)
    raw_body = (await request.body()).decode("utf-8", errors="replace")

    # Логи в консоль — чтобы увидеть, что реально приходит
    print("\n=== Dahua AutoRegist ===", flush=True)
    print("IP:", client_ip, flush=True)
    print("Method:", method, flush=True)
    print("Path:", path, flush=True)
    print("Headers:", dict(request.headers), flush=True)
    print("Parsed payload:", payload, flush=True)
    if raw_body:
        print("Raw body:", raw_body, flush=True)

    serial = upsert_device(client_ip, path, method, payload, raw_body)
    action = (rest.split("/", 1)[0] if rest else "").strip()
    response_payload = autoregist_response(action, serial, request, payload)
    print("Response body:", json.dumps(response_payload, ensure_ascii=False), flush=True)
    return JSONResponse(response_payload, status_code=200, headers={"Cache-Control": "no-store"})


# Иногда Dahua дергает OPTIONS (CORS/Preflight) или странные проверки
@app.options("/{any_path:path}")
def options(any_path: str):
    return PlainTextResponse("OK", status_code=200)


if __name__ == "__main__":
    init_db()
    import uvicorn

    uvicorn.run(app, host=LISTEN_HOST, port=LISTEN_PORT)
