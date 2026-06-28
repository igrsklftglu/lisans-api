# -*- coding: utf-8 -*-
"""
Admin CLI - Lisans anahtari uretme araci
Kullanim: python generate_key.py <email> <plan>

Planlar: 0suresiz, 1month, 3month, 6month, 12month
Ornek: python generate_key.py musteri@email.com 1month
"""
import sys
import os
import json
import hmac
import hashlib
import base64
import re
from datetime import datetime, timedelta

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

SECRET_KEY = os.environ.get('LICENSE_SECRET', '5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e')
PLANS = {
    "0suresiz": "suresiz",
    "1month": "1month",
    "3month": "3month",
    "6month": "6month",
    "12month": "12month",
}
PLAN_DAYS = {
    "1month": 30,
    "3month": 90,
    "6month": 180,
    "12month": 365,
}

def generate_key(email: str, plan: str) -> str:
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        print(f"Hata: Geçersiz email '{email}'")
        sys.exit(1)

    if plan not in PLANS:
        print(f"Hata: Geçersiz plan '{plan}'. Seçenekler: {', '.join(PLANS.keys())}")
        sys.exit(1)

    plan_adi = PLANS[plan]
    if plan_adi == "suresiz":
        expiry_ymd = "00000000"
    else:
        expiry_ymd = (datetime.now() + timedelta(days=PLAN_DAYS[plan])).strftime("%Y%m%d")

    payload = f"{email}|{plan_adi}|{expiry_ymd}"
    signature = hmac.new(
        SECRET_KEY.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()[:16]

    raw = f"{payload}|{signature}"
    key = base64.b64encode(raw.encode()).decode()
    return key, {"email": email, "plan": plan, "key": key, "expiry": expiry_ymd}

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Kullanim: python generate_key.py <email> <plan>")
        print("Planlar: 0suresiz, 1month, 3month, 6month, 12month")
        print("\nOrnek: python generate_key.py musteri@email.com 1month")
        sys.exit(1)

    email = sys.argv[1]
    plan = sys.argv[2]
    key, entry = generate_key(email, plan)

    print("\n" + "=" * 50)
    print("LISANS ANAHTARI OLUSTURULDU")
    print("=" * 50)
    print(f"Email     : {email}")
    print(f"Plan      : {plan}")
    print(f"Bitiş     : {entry['expiry']}")
    print(f"Anahtar   : {key}")
    print("=" * 50)
    print("\nKullaniciya ilet:")
    print(key)
