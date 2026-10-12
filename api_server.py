import os
import json
import hmac
import hashlib
import base64
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, abort, redirect, url_for

import signing

app = Flask(__name__)

SECRET_KEY = os.environ.get('LICENSE_SECRET', '5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e')
ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN', '').strip()
if not ADMIN_TOKEN:
    raise RuntimeError("ADMIN_TOKEN ortam degiskeni tanimli degil. Guvenlik icin zorunludur.")

# --- Ed25519 lisans imzalama anahtarlari (yeni "v2" format) ---
# Ozel anahtar SADECE sunucuda (Render env LICENSE_PRIVATE_KEY). Istenirse
# yuksek seviye acik anahtar da verilebilir; yoksa ozelden turetilir.
_PK_B64 = os.environ.get('LICENSE_PRIVATE_KEY', '')
_PUB_B64 = os.environ.get('LICENSE_PUBLIC_KEY', '')

_KEYS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'signing_keys.local.json')
if (not _PK_B64) and os.path.exists(_KEYS_FILE):
    try:
        with open(_KEYS_FILE, 'r', encoding='utf-8') as _f:
            _kd = json.load(_f)
        _PK_B64 = _PK_B64 or _kd.get('LICENSE_PRIVATE_KEY', '')
        _PUB_B64 = _PUB_B64 or _kd.get('LICENSE_PUBLIC_KEY', '')
    except Exception:
        pass


def _b64d(s):
    try:
        return base64.b64decode(s) if s else None
    except Exception:
        return None


PRIVATE_KEY = _b64d(_PK_B64)
PUBLIC_KEY = _b64d(_PUB_B64)
if PUBLIC_KEY is None and PRIVATE_KEY is not None:
    PUBLIC_KEY = signing.publickey(PRIVATE_KEY)

# --- Database abstraction ---
USE_PG = False

_PG_URL = os.environ.get("DATABASE_URL", "")
if _PG_URL:
    try:
        import psycopg2
        import psycopg2.extras
        _test = psycopg2.connect(_PG_URL, connect_timeout=5)
        _test.close()
        USE_PG = True
        print("PostgreSQL baglantisi basarili!")
    except Exception as e:
        print(f"PostgreSQL baglantisi basarisiz: {e}. SQLite kullanilacak.")
        USE_PG = False

if USE_PG:
    _pg_cursor_factory = psycopg2.extras.RealDictCursor

    def get_db():
        conn = psycopg2.connect(_PG_URL)
        conn.autocommit = True
        return conn

    def _q(sql):
        return sql.replace("?", "%s")

    def _row_factory(cur):
        return [dict(r) for r in cur.fetchall()]

    def init_db():
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(_q('''
                CREATE TABLE IF NOT EXISTS licenses (
                    id SERIAL PRIMARY KEY,
                    email TEXT NOT NULL,
                    plan TEXT NOT NULL,
                    hesap TEXT DEFAULT '',
                    key_hash TEXT NOT NULL UNIQUE,
                    expiry TEXT NOT NULL,
                    activated_at TEXT,
                    last_check_at TEXT,
                    activation_ip TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            '''))
            cur.execute(_q('CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(email);'))
            cur.execute(_q('ALTER TABLE licenses ADD COLUMN IF NOT EXISTS legacy_key_hash TEXT;'))
        conn.close()

else:
    import sqlite3

    DB_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_PATH = os.path.join(DB_DIR, "licenses.db")

    def get_db():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def _q(sql):
        return sql

    def _row_factory(cur):
        return [dict(r) for r in cur.fetchall()]

    def init_db():
        conn = get_db()
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute('''
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                plan TEXT NOT NULL,
                hesap TEXT DEFAULT '',
                key_hash TEXT NOT NULL UNIQUE,
                expiry TEXT NOT NULL,
                activated_at TEXT,
                last_check_at TEXT,
                activation_ip TEXT,
                is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now'))
            );
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(email);')
        try:
            conn.execute('ALTER TABLE licenses ADD COLUMN legacy_key_hash TEXT')
        except Exception:
            pass
        conn.commit()
        conn.close()


def db_execute(sql, params=None, fetch=True):
    conn = get_db()
    if USE_PG:
        cur = conn.cursor(cursor_factory=_pg_cursor_factory)
    else:
        cur = conn.cursor()
    try:
        if USE_PG:
            cur.execute(_q(sql), params or ())
        else:
            cur.execute(sql, params or ())
            conn.commit()
        if fetch:
            return _row_factory(cur)
        return None
    finally:
        conn.close()


PLAN_DAYS = {"1month": 30, "3month": 90, "6month": 180, "9month": 270, "12month": 365}
PLAN_LIFETIME = ("suresiz", "0suresiz")


def generate_key(email: str, plan: str, hesap: str = "", expiry_ymd: str = "") -> tuple:
    if not expiry_ymd:
        if plan in PLAN_LIFETIME:
            expiry_ymd = "00000000"
        else:
            days = PLAN_DAYS.get(plan, 30)
            expiry_ymd = (datetime.now() + timedelta(days=days)).strftime("%Y%m%d")
    if PRIVATE_KEY is not None:
        # Yeni v2: Ed25519 OZEL anahtarla imzalanir
        payload = f"v2|{email}|{plan}|{expiry_ymd}|{hesap.strip()}"
        sig = base64.b64encode(signing.sign(payload.encode(), PRIVATE_KEY)).decode()
    else:
        # Ozel anahtar tanimli degilse eski v1 (HMAC) ile uret
        payload = f"{email}|{plan}|{expiry_ymd}|{hesap.strip()}"
        sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    key = base64.b64encode(f"{payload}|{sig}".encode()).decode()
    return key, expiry_ymd


def verify_key_on_server(key: str, email: str) -> dict:
    try:
        raw = base64.b64decode(key.encode()).decode()

        # --- Yeni v2 (Ed25519) ---
        if raw.startswith("v2|"):
            parts = raw.split("|")
            if len(parts) != 6:
                return {"valid": False, "reason": "Geçersiz anahtar formatı"}
            _, k_email, k_plan, k_expiry, k_hesap, k_sig_b64 = parts
            if PUBLIC_KEY is None:
                return {"valid": False, "reason": "Sunucu imza anahtarı tanımlı değil"}
            try:
                sig_bytes = base64.b64decode(k_sig_b64)
            except Exception:
                return {"valid": False, "reason": "Geçersiz anahtar formatı"}
            payload = f"v2|{k_email}|{k_plan}|{k_expiry}|{k_hesap}"
            if not signing.verify(sig_bytes, payload.encode(), PUBLIC_KEY):
                return {"valid": False, "reason": "Geçersiz imza"}
            if k_plan not in PLAN_DAYS and k_plan not in PLAN_LIFETIME:
                return {"valid": False, "reason": "Geçersiz plan"}
            if email and email.lower() != k_email.lower():
                return {"valid": False, "reason": "Email uyuşmuyor"}
            return {
                "valid": True,
                "email": k_email,
                "plan": k_plan,
                "expiry": k_expiry,
                "hesap": k_hesap,
            }

        # --- Eski v1 (HMAC) ---
        parts = raw.split("|")

        k_hesap = ""
        if len(parts) == 5:
            k_email, k_plan, k_expiry, k_hesap, k_sig = parts
            if len(k_expiry) == 8 and k_expiry.isdigit():
                payload = f"{k_email}|{k_plan}|{k_expiry}|{k_hesap}"
            else:
                return {"valid": False, "reason": "Geçersiz anahtar formatı"}
        elif len(parts) == 4:
            k_email, k_plan, k_expiry, k_sig = parts
            if len(k_expiry) == 8 and k_expiry.isdigit():
                payload = f"{k_email}|{k_plan}|{k_expiry}"
            else:
                return {"valid": False, "reason": "Geçersiz anahtar formatı"}
        elif len(parts) == 3:
            k_email, k_plan, k_sig = parts
            k_expiry = ""
            payload = f"{k_email}|{k_plan}"
        else:
            return {"valid": False, "reason": "Geçersiz anahtar formatı"}

        sig = hmac.new(
            SECRET_KEY.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()[:16]
        if not hmac.compare_digest(k_sig, sig):
            return {"valid": False, "reason": "Geçersiz imza"}

        if email and email.lower() != k_email.lower():
            return {"valid": False, "reason": "Email uyuşmuyor"}

        return {
            "valid": True,
            "email": k_email,
            "plan": k_plan,
            "expiry": k_expiry if len(parts) >= 4 else "",
            "hesap": k_hesap,
        }
    except Exception as e:
        return {"valid": False, "reason": f"Anahtar çözülemedi: {str(e)}"}


def _key_is_v2(key: str) -> bool:
    try:
        return base64.b64decode(key.encode()).decode().startswith("v2|")
    except Exception:
        return False


def _row_expiry_ymd(row) -> str:
    """DB satirindan anahtara gomulecek expiry (lifetime -> 00000000)."""
    plan = row["plan"]
    if plan in PLAN_LIFETIME:
        return "00000000"
    e = str(row["expiry"] or "").strip()
    if len(e) == 8 and e.isdigit():
        return e
    return ""


def maybe_reissue_key(row, key: str, supports_v2: bool):
    """Yeni istemci icin: mevcut anahtar DB ile uyusmuyorsa, ayni plan/sure/hesapla
    yeni bir v2 anahtar uretir; DB'yi gunceller ve yeni anahtari dondurur.
    Gerek yoksa None dondurur. (Ed25519 imzalari deterministiktir.)"""
    if not supports_v2 or PRIVATE_KEY is None:
        return None
    try:
        plan = row["plan"]
        hesap = str(row["hesap"] or "")
        email = row["email"]
        exp = _row_expiry_ymd(row)
        canon_key, _ = generate_key(email, plan, hesap, expiry_ymd=exp)
        if canon_key == key:
            return None
        old_hash = hashlib.sha256(key.encode()).hexdigest()
        new_hash = hashlib.sha256(canon_key.encode()).hexdigest()
        db_execute(
            "UPDATE licenses SET key_hash = ?, legacy_key_hash = ? WHERE id = ?",
            (new_hash, old_hash, row["id"]),
            fetch=False,
        )
        return canon_key
    except Exception as e:
        print(f"Anahtar yukseltme hatasi: {e}")
        return None


def kalan_gun(expiry: str, plan: str) -> int:
    if plan in PLAN_LIFETIME or expiry == "20991231" or expiry == "00000000":
        return -1
    try:
        dt = datetime.strptime(expiry, "%Y%m%d")
        return max(0, (dt - datetime.now()).days)
    except:
        return 0


def get_real_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "v7", "pg": USE_PG, "time": datetime.now().isoformat()})


UPDATE_INFO_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "update_info.json")


def _load_update_info() -> dict:
    """En son surum bilgisini dondurur: update_info.json + env (UPDATE_*) oncelikli."""
    info = {
        "last_version": "1.1.6",
        "download_url": "",
        "sha256": "",
        "release_notes": "",
    }
    try:
        if os.path.exists(UPDATE_INFO_FILE):
            with open(UPDATE_INFO_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                info.update({k: v for k, v in data.items() if k in info and v})  
    except Exception as e:
        print(f"update_info.json okunamadi: {e}")

    env_map = {
        "last_version": "UPDATE_LATEST_VERSION",
        "download_url": "UPDATE_DOWNLOAD_URL",
        "sha256": "UPDATE_SHA256",
        "release_notes": "UPDATE_NOTES",
    }
    for key, env_var in env_map.items():
        val = os.environ.get(env_var, "")
        if val:
            info[key] = val
    return info


@app.route("/api/update", methods=["GET"])
def update_info():
    info = _load_update_info()
    return jsonify({
        "product": "XAUUSD_XAUEUR",
        "last_version": info["last_version"],
        "download_url": info["download_url"],
        "sha256": info["sha256"],
        "release_notes": info["release_notes"],
        "checked_at": datetime.now().isoformat(),
    })


@app.route("/api/register", methods=["POST"])
def register():
    if ADMIN_TOKEN:
        token = request.args.get("token", "")
        if not token:
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token != ADMIN_TOKEN:
            return jsonify({"error": "Yetkisiz erişim"}), 401
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    plan = data.get("plan", "").strip()
    hesap = data.get("hesap", "").strip()

    if not email or not hesap:
        return jsonify({"success": False, "error": "Email ve hesap numarası zorunlu"}), 400

    key, expiry_ymd = generate_key(email, plan, hesap)
    key_hash = hashlib.sha256(key.encode()).hexdigest()

    try:
        db_execute(
            "INSERT INTO licenses (email, plan, hesap, key_hash, expiry) VALUES (?, ?, ?, ?, ?)",
            (email, plan, hesap, key_hash, ""),
            fetch=False
        )
    except Exception:
        return jsonify({"success": False, "error": "Bu email için zaten bir anahtar var"}), 409

    return jsonify({
        "success": True,
        "key": key,
        "expiry": expiry_ymd,
        "email": email,
        "plan": plan
    })


@app.route("/api/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    key = data.get("key", "").strip()
    email = data.get("email", "").strip().lower()
    giris_hesap = data.get("hesap", "").strip().lower()

    if not key or not email:
        return jsonify({"valid": False, "reason": "Eksik bilgi"}), 400

    sig_result = verify_key_on_server(key, email)
    if not sig_result["valid"]:
        return jsonify(sig_result)

    plan = sig_result["plan"]
    expiry = sig_result["expiry"]

    key_hash = hashlib.sha256(key.encode()).hexdigest()
    rows = db_execute("SELECT * FROM licenses WHERE key_hash = ?", (key_hash,))
    if not rows:
        return jsonify({
            "valid": False,
            "reason": "Bu anahtar sistemde kayıtlı değil. Satıcınızla iletişime geçin."
        })
    row = rows[0]

    hesap = (str(row["hesap"] or "").strip() or str(sig_result.get("hesap") or "").strip())

    # Girilen hesap key'e veya DB'ye bagli hesapla eslesmeli
    if giris_hesap and hesap and giris_hesap != hesap.lower():
        return jsonify({
            "valid": False,
            "reason": "Bu anahtar bu hesap numarasına bağlı değil"
        })

    if plan in PLAN_LIFETIME:
        db_expiry = "20991231"
    else:
        db_expiry = (datetime.now() + timedelta(days=PLAN_DAYS.get(plan, 30))).strftime("%Y%m%d")

    if row["activated_at"] is None:
        db_execute(
            "UPDATE licenses SET activated_at = ?, activation_ip = ?, expiry = ? WHERE id = ?",
            (datetime.now().isoformat(), get_real_ip(), db_expiry, row["id"]),
            fetch=False
        )
    else:
        db_execute(
            "UPDATE licenses SET activation_ip = ?, last_check_at = ? WHERE id = ?",
            (get_real_ip(), datetime.now().isoformat(), row["id"]),
            fetch=False
        )
        if row["expiry"]:
            db_expiry = row["expiry"]

    if plan in PLAN_LIFETIME or db_expiry == "20991231":
        remaining = -1
        expiry_display = "2099-12-31"
    else:
        try:
            expiry_dt = datetime.strptime(db_expiry, "%Y%m%d")
            if expiry_dt < datetime.now():
                return jsonify({
                    "valid": False,
                    "reason": "Bu anahtarın süresi dolmuş. Yeni bir anahtar satın alın."
                })
            remaining = kalan_gun(db_expiry, plan)
            expiry_display = expiry_dt.strftime("%Y-%m-%d")
        except:
            return jsonify({"valid": False, "reason": "Anahtar tarihi geçersiz"})

    return jsonify({
        "valid": True,
        "email": email,
        "plan": plan,
        "expiry": expiry_display,
        "remaining_days": remaining,
        "hesap": hesap
    })


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    key = data.get("key", "").strip()
    email = data.get("email", "").strip().lower()
    giris_hesap = data.get("hesap", "").strip().lower()
    supports_v2 = bool(data.get("v2"))

    if not key or not email:
        return jsonify({"valid": False, "reason": "Eksik bilgi"}), 400

    key_hash = hashlib.sha256(key.encode()).hexdigest()
    rows = db_execute(
        "SELECT * FROM licenses WHERE key_hash = ? OR legacy_key_hash = ?",
        (key_hash, key_hash),
    )
    if not rows:
        return jsonify({"valid": False, "reason": "Anahtar bulunamadı"})
    row = rows[0]

    hesap = str(row["hesap"] or "").strip()

    # Girilen hesap DB'deki hesapla eslesmeli
    if giris_hesap and hesap and giris_hesap != hesap.lower():
        return jsonify({"valid": False, "reason": "Hesap uyusmazligi: Bu anahtar bu hesap numarasına bağlı değil"})

    plan = row["plan"]
    expiry = row["expiry"]

    db_execute(
        "UPDATE licenses SET last_check_at = ?, activation_ip = ? WHERE id = ?",
        (datetime.now().isoformat(), get_real_ip(), row["id"]),
        fetch=False
    )

    if not expiry:
        return jsonify({
            "valid": False,
            "reason": "Bu anahtar henüz aktif edilmemiş"
        })

    if plan in PLAN_LIFETIME or expiry == "20991231":
        new_key = maybe_reissue_key(row, key, supports_v2)
        resp = {
            "valid": True,
            "remaining_days": -1,
            "expiry": "2099-12-31",
            "hesap": hesap
        }
        if new_key:
            resp["new_key"] = new_key
        return jsonify(resp)

    try:
        expiry_dt = datetime.strptime(expiry, "%Y%m%d")
        if expiry_dt < datetime.now():
            return jsonify({
                "valid": False,
                "remaining_days": 0,
                "expiry": expiry_dt.strftime("%Y-%m-%d"),
                "reason": "Lisans süresi doldu"
            })
        remaining = kalan_gun(expiry, plan)
        new_key = maybe_reissue_key(row, key, supports_v2)
        resp = {
            "valid": True,
            "remaining_days": remaining,
            "expiry": expiry_dt.strftime("%Y-%m-%d"),
            "hesap": hesap
        }
        if new_key:
            resp["new_key"] = new_key
        return jsonify(resp)
    except:
        return jsonify({"valid": False, "reason": "Tarih hatası"})


@app.route("/api/update_hesap", methods=["POST"])
def update_hesap():
    if ADMIN_TOKEN:
        token = request.args.get("token", "")
        if not token:
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token != ADMIN_TOKEN:
            return jsonify({"error": "Yetkisiz erişim"}), 401
    data = request.get_json(silent=True) or {}
    lid = data.get("id")
    new_hesap = str(data.get("hesap", "")).strip()

    if not lid:
        return jsonify({"success": False, "error": "ID gerekli"}), 400
    if not new_hesap or not new_hesap.isdigit():
        return jsonify({"success": False, "error": "Geçerli bir hesap numarası girin"}), 400

    rows = db_execute("SELECT * FROM licenses WHERE id = ?", (lid,))
    if not rows:
        return jsonify({"success": False, "error": "Kayıt bulunamadı"}), 404
    row = rows[0]

    db_execute(
        "UPDATE licenses SET hesap = ? WHERE id = ?",
        (new_hesap, lid),
        fetch=False
    )

    # Hesap degisince lisans anahtari da yeniden uretilir (imza hesabi kapsar)
    new_key = None
    try:
        exp = _row_expiry_ymd(row)
        old_hash = str(row["key_hash"] or "")
        new_key, _ = generate_key(row["email"], row["plan"], new_hesap, expiry_ymd=exp)
        new_hash = hashlib.sha256(new_key.encode()).hexdigest()
        db_execute(
            "UPDATE licenses SET key_hash = ?, legacy_key_hash = ? WHERE id = ?",
            (new_hash, old_hash, lid),
            fetch=False
        )
    except Exception as e:
        return jsonify({"success": False, "error": f"Anahtar üretilemedi: {e}"}), 500

    return jsonify({
        "success": True,
        "hesap": new_hesap,
        "key": new_key,
        "key_degismedi": False
    })


@app.route("/api/delete", methods=["POST"])
def delete_licenses():
    if ADMIN_TOKEN:
        token = request.args.get("token", "")
        if not token:
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token != ADMIN_TOKEN:
            return jsonify({"error": "Yetkisiz erişim"}), 401
    data = request.get_json(silent=True) or {}
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"success": False, "error": "ID gerekli"}), 400
    placeholders = ",".join("?" for _ in ids)
    db_execute(f"DELETE FROM licenses WHERE id IN ({placeholders})", ids, fetch=False)
    return jsonify({"success": True, "deleted": len(ids)})


@app.route("/")
def dashboard():
    token = request.args.get("token", "")
    if token != ADMIN_TOKEN:
        return render_template("dashboard.html",
                               authorized=False,
                               token=ADMIN_TOKEN)

    rows = db_execute("SELECT * FROM licenses ORDER BY created_at DESC")

    records = []
    for r in rows:
        now = datetime.now()
        plan = r["plan"]
        expiry = r["expiry"]

        def _str(val):
            if val is None: return "-"
            if isinstance(val, datetime): return val.isoformat()
            return str(val)

        if plan in PLAN_LIFETIME or expiry == "20991231" or expiry == "00000000":
            status = "Süresiz"
            remaining = -1
            expiry_display = "Süresiz"
        else:
            try:
                expiry_dt = datetime.strptime(expiry, "%Y%m%d")
                expiry_display = expiry_dt.strftime("%d.%m.%Y")
                if r["activated_at"] is None:
                    status = "Aktif Edilmedi"
                    remaining = -1
                elif expiry_dt < now:
                    status = "Süresi Doldu"
                    remaining = 0
                else:
                    status = "Aktif"
                    remaining = (expiry_dt - now).days
            except:
                status = "Hatalı"
                remaining = -1
                expiry_display = expiry

        records.append({
            "id": r["id"],
            "email": r["email"],
            "plan": plan,
            "hesap": r["hesap"],
            "expiry": expiry_display,
            "remaining": remaining,
            "status": status,
            "activated_at": _str(r["activated_at"]),
            "last_check_at": _str(r["last_check_at"]),
            "ip": _str(r["activation_ip"]),
            "created_at": _str(r["created_at"])
        })

    return render_template("dashboard.html",
                           authorized=True,
                           token=ADMIN_TOKEN,
                           records=records,
                           PLAN_DAYS=PLAN_DAYS,
                           PLAN_LIFETIME=PLAN_LIFETIME)


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
