"""
License API Server - Lisans doğrulama sunucusu
Çalıştır: python app.py
"""
import sqlite3
import hmac
import hashlib
import base64
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

SECRET_KEY = '5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e'
ADMIN_TOKEN = "admin-sifre-buraya"

def get_db():
    conn = sqlite3.connect("licenses.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            account_no TEXT NOT NULL,
            plan TEXT NOT NULL,
            expiry TEXT NOT NULL,
            created_at TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            hardware_id TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT,
            account_no TEXT,
            action TEXT,
            ip TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def verify_key_format(key: str) -> dict:
    """Anahtar formatını doğrula ve içeriğini çöz"""
    try:
        raw = base64.b64decode(key.encode()).decode()
        parts = raw.split("|")
        if len(parts) != 4:
            return {"valid": False, "reason": "Geçersiz format"}

        account_no, expiry, plan, signature = parts
        payload = f"{account_no}|{expiry}|{plan}"
        expected_sig = hmac.new(
            SECRET_KEY.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()[:16]

        if not hmac.compare_digest(signature, expected_sig):
            return {"valid": False, "reason": "Anahtar imzası geçersiz"}

        return {
            "valid": True,
            "account_no": account_no,
            "expiry": expiry,
            "plan": plan,
        }
    except Exception as e:
        return {"valid": False, "reason": f"Anahtar çözülemedi: {str(e)}"}

@app.route("/verify", methods=["POST"])
def verify():
    """Anahtar doğrulama - Bot buraya sorgu atar"""
    data = request.get_json()
    if not data:
        return jsonify({"valid": False, "reason": "JSON gerekli"}), 400

    key = data.get("key", "").strip()
    account_no = data.get("account_no", "").strip()
    hardware_id = data.get("hardware_id", "")

    if not key or not account_no:
        return jsonify({"valid": False, "reason": "Key ve hesap no gerekli"}), 400

    # Format kontrolü
    decoded = verify_key_format(key)
    if not decoded["valid"]:
        return jsonify(decoded)

    # Hesap no eşleşmesi
    if decoded["account_no"] != account_no:
        return jsonify({"valid": False, "reason": "Bu anahtar bu hesap numarasına ait değil"})

    # Veritabanında ara
    conn = get_db()
    row = conn.execute("SELECT * FROM licenses WHERE key = ?", (key,)).fetchone()
    conn.close()

    if not row:
        return jsonify({"valid": False, "reason": "Anahtar bulunamadı"})

    if not row["active"]:
        return jsonify({"valid": False, "reason": "Anahtar devre dışı bırakıldı"})

    # Süre kontrolü
    expiry_date = datetime.strptime(row["expiry"], "%Y%m%d")
    if expiry_date < datetime.now():
        return jsonify({"valid": False, "reason": "Lisans süresi doldu"})

    # Hardware ID güncelle (ilk girişte)
    conn = get_db()
    if row["hardware_id"] is None and hardware_id:
        conn.execute("UPDATE licenses SET hardware_id = ? WHERE key = ?",
                     (hardware_id, key))
        conn.commit()
    conn.close()

    # Log
    log_request(key, account_no, "verify", request.remote_addr)

    return jsonify({
        "valid": True,
        "account_no": row["account_no"],
        "expiry": row["expiry"],
        "plan": row["plan"],
        "remaining_days": (expiry_date - datetime.now()).days,
    })

@app.route("/admin/generate", methods=["POST"])
def admin_generate():
    """Admin: Yeni anahtar üret"""
    data = request.get_json()
    if data.get("token") != ADMIN_TOKEN:
        return jsonify({"error": "Yetkisiz"}), 403

    from generate_key import generate_key
    key, db_entry = generate_key(data["account_no"], data["plan"])
    return jsonify({"key": key, "details": db_entry})

@app.route("/admin/list", methods=["POST"])
def admin_list():
    """Admin: Tüm anahtarları listele"""
    data = request.get_json()
    if data.get("token") != ADMIN_TOKEN:
        return jsonify({"error": "Yetkisiz"}), 403

    conn = get_db()
    rows = conn.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/admin/deactivate", methods=["POST"])
def admin_deactivate():
    """Admin: Anahtarı devre dışı bırak"""
    data = request.get_json()
    if data.get("token") != ADMIN_TOKEN:
        return jsonify({"error": "Yetkisiz"}), 403

    conn = get_db()
    conn.execute("UPDATE licenses SET active = 0 WHERE key = ?", (data["key"],))
    conn.commit()
    conn.close()
    return jsonify({"status": "deactivated"})

def log_request(key, account_no, action, ip):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO logs (key, account_no, action, ip, timestamp) VALUES (?, ?, ?, ?, ?)",
            (key, account_no, action, ip, datetime.now().isoformat()),
        )
        conn.commit()
        conn.close()
    except:
        pass

if __name__ == "__main__":
    init_db()
    print("=" * 50)
    print("License API Server Başlatıldı")
    print(f"Admin Panel: http://localhost:5000/admin")
    print(f"Doğrulama:   POST http://localhost:5000/verify")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=True)
