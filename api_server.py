import os
import json
import hmac
import hashlib
import base64
import sqlite3
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, abort, redirect, url_for

app = Flask(__name__)

SECRET_KEY = os.environ.get('LICENSE_SECRET', '5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e')
ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN', 'admin123')

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, 'licenses.db')

PLAN_DAYS = {"1month": 30, "3month": 90, "6month": 180, "12month": 365}
PLAN_LIFETIME = ("suresiz", "0suresiz")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            token = request.args.get("token", "")
        if not token:
            data = request.get_json(silent=True) or {}
            token = data.get("token", "")
        if not token or token != ADMIN_TOKEN:
            return jsonify({"error": "Yetkisiz erişim"}), 401
        return f(*args, **kwargs)
    return decorated


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.now().isoformat()})


@app.route("/api/register", methods=["POST"])
@token_required
def register():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    plan = data.get("plan", "").strip()
    hesap = data.get("hesap", "").strip()

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"success": False, "error": "Geçersiz email"}), 400

    if plan not in PLAN_DAYS and plan not in PLAN_LIFETIME:
        return jsonify({"success": False, "error": "Geçersiz plan"}), 400

    key, expiry_ymd = generate_key(email, plan)
    key_hash = hashlib.sha256(key.encode()).hexdigest()

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO licenses (email, plan, hesap, key_hash, expiry) VALUES (?, ?, ?, ?, ?)",
            (email, plan, hesap, key_hash, "")
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"success": False, "error": "Bu email için zaten bir anahtar var"}), 409
    conn.close()

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
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM licenses WHERE key_hash = ?", (key_hash,)
    ).fetchone()

    if not row:
        conn.close()
        return jsonify({
            "valid": False,
            "reason": "Bu anahtar sistemde kayıtlı değil. Satıcınızla iletişime geçin."
        })

    if plan in PLAN_LIFETIME:
        db_expiry = "20991231"
    else:
        db_expiry = (datetime.now() + timedelta(days=PLAN_DAYS.get(plan, 30))).strftime("%Y%m%d")

    if row["activated_at"] is None:
        conn.execute(
            "UPDATE licenses SET activated_at = ?, activation_ip = ?, expiry = ? WHERE id = ?",
            (datetime.now().isoformat(), get_real_ip(), db_expiry, row["id"])
        )
        conn.commit()
    else:
        conn.execute(
            "UPDATE licenses SET activation_ip = ?, last_check_at = ? WHERE id = ?",
            (get_real_ip(), datetime.now().isoformat(), row["id"])
        )
        if row["expiry"]:
            db_expiry = row["expiry"]
        conn.commit()

    conn.close()

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
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM licenses WHERE key_hash = ?", (key_hash,)
    ).fetchone()

    if not row:
        conn.close()
        return jsonify({"valid": False, "reason": "Anahtar bulunamadı"})

    plan = row["plan"]
    expiry = row["expiry"]

    conn.execute(
        "UPDATE licenses SET last_check_at = ?, activation_ip = ? WHERE id = ?",
        (datetime.now().isoformat(), get_real_ip(), row["id"])
    )
    conn.commit()
    conn.close()

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


@app.route("/")
def dashboard():
    token = request.args.get("token", "")
    if token != ADMIN_TOKEN:
        return render_template("dashboard.html",
                               authorized=False,
                               token=ADMIN_TOKEN)

    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM licenses ORDER BY created_at DESC"
    ).fetchall()
    conn.close()

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
