import os
import json
import hmac
import hashlib
import base64
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, abort, redirect, url_for

app = Flask(__name__)

SECRET_KEY = os.environ.get('LICENSE_SECRET', '5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e')
ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN', 'benimtoken123')

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
        conn.commit()
        conn.close()


def db_execute(sql, params=None, fetch=True):
    conn = get_db()
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


PLAN_DAYS = {"1month": 30, "3month": 90, "6month": 180, "12month": 365}
PLAN_LIFETIME = ("suresiz", "0suresiz")


def generate_key(email: str, plan: str) -> tuple:
    if plan in PLAN_LIFETIME:
        expiry_ymd = "00000000"
    else:
        days = PLAN_DAYS.get(plan, 30)
        expiry_ymd = (datetime.now() + timedelta(days=days)).strftime("%Y%m%d")
    payload = f"{email}|{plan}|{expiry_ymd}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    key = base64.b64encode(f"{payload}|{sig}".encode()).decode()
    return key, expiry_ymd


def verify_key_on_server(key: str, email: str) -> dict:
    try:
        raw = base64.b64decode(key.encode()).decode()
        parts = raw.split("|")

        if len(parts) == 4:
            k_email, k_plan, k_expiry, k_sig = parts
            if len(k_expiry) == 8 and k_expiry.isdigit():
                payload = f"{k_email}|{k_plan}|{k_expiry}"
            else:
                return {"valid": False, "reason": "Geçersiz anahtar formatı"}
        elif len(parts) == 3:
            k_email, k_plan, k_sig = parts
            payload = f"{k_email}|{k_plan}"
        else:
            return {"valid": False, "reason": "Geçersiz anahtar formatı"}

        expected_sig = hmac.new(
            SECRET_KEY.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()[:16]

        if not hmac.compare_digest(k_sig, expected_sig):
            return {"valid": False, "reason": "Anahtar imzası geçersiz (sahte anahtar)"}

        if k_email.lower() != email.lower():
            return {"valid": False, "reason": "Bu anahtar bu email adresine ait değil"}

        if k_plan not in PLAN_DAYS and k_plan not in PLAN_LIFETIME:
            return {"valid": False, "reason": "Geçersiz plan"}

        return {"valid": True, "email": k_email, "plan": k_plan, "expiry": k_expiry}

    except Exception as e:
        return {"valid": False, "reason": f"Anahtar çözülemedi: {str(e)}"}


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
    return jsonify({"status": "ok", "version": "v6", "pg": USE_PG, "time": datetime.now().isoformat()})


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

    key, expiry_ymd = generate_key(email, plan)
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
        "remaining_days": remaining
    })


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    key = data.get("key", "").strip()
    email = data.get("email", "").strip().lower()

    if not key or not email:
        return jsonify({"valid": False, "reason": "Eksik bilgi"}), 400

    key_hash = hashlib.sha256(key.encode()).hexdigest()
    rows = db_execute("SELECT * FROM licenses WHERE key_hash = ?", (key_hash,))
    if not rows:
        return jsonify({"valid": False, "reason": "Anahtar bulunamadı"})
    row = rows[0]

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
        return jsonify({
            "valid": True,
            "remaining_days": -1,
            "expiry": "2099-12-31"
        })

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
        return jsonify({
            "valid": True,
            "remaining_days": remaining,
            "expiry": expiry_dt.strftime("%Y-%m-%d")
        })
    except:
        return jsonify({"valid": False, "reason": "Tarih hatası"})


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
            "activated_at": r["activated_at"] or "-",
            "last_check_at": r["last_check_at"] or "-",
            "ip": r["activation_ip"] or "-",
            "created_at": r["created_at"]
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
