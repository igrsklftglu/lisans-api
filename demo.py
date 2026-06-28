# -*- coding: utf-8 -*-
"""Demo: Lisans sistemi nasil calisir"""

import hmac, hashlib, base64
from datetime import datetime, timedelta

SECRET = "5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e"

def key_uret(hesap_no, plan_gun):
    bitis = (datetime.now() + timedelta(days=plan_gun)).strftime("%Y%m%d")
    payload = f"{hesap_no}|{bitis}|{plan_gun}gun"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    return base64.b64encode(f"{payload}|{sig}".encode()).decode(), bitis

def key_dogrula(key, hesap_no):
    try:
        raw = base64.b64decode(key.encode()).decode()
        parts = raw.split("|")
        if len(parts) != 4:
            return False, "Gecersiz format"

        k_hesap, k_bitis, k_plan, k_imza = parts

        # Imza kontrol
        expected = hmac.new(SECRET.encode(),
            f"{k_hesap}|{k_bitis}|{k_plan}".encode(),
            hashlib.sha256).hexdigest()[:16]

        if k_imza != expected:
            return False, "Gecersiz imza"

        # Hesap no kontrol
        if k_hesap != hesap_no:
            return False, "Bu key baska hesaba ait"

        # Tarih kontrol
        bitis = datetime.strptime(k_bitis, "%Y%m%d")
        if bitis < datetime.now():
            return False, f"Lisans suresi doldu ({k_bitis})"

        kalan = (bitis - datetime.now()).days
        return True, f"Gecerli! {kalan} gun kaldi (son: {k_bitis})"

    except Exception as e:
        return False, str(e)


# ===== DEMO =====
print("=" * 60)
print("LISANS SISTEMI DEMO")
print("=" * 60)

# 1. Admin key uretiyor
print("\n1. ADMIN KEY URETIYOR (python generate_key.py 12345678 1month)")
key, bitis = key_uret("12345678", 30)
print(f"   Hesap: 12345678")
print(f"   Key:   {key}")
print(f"   Gecerli: {datetime.now().strftime('%Y-%m-%d')} -> {bitis}")
print()

# 2. Kullanici key'i giriyor (dogru hesap)
print("2. KULLANICI KEY'I GIRIYOR (dogru hesap: 12345678)")
ok, msg = key_dogrula(key, "12345678")
print(f"   {msg}")
print()

# 3. Kullanici key'i giriyor (yanlis hesap)
print("3. KULLANICI KEY'I GIRIYOR (yanlis hesap: 87654321)")
ok, msg = key_dogrula(key, "87654321")
print(f"   {msg}")
print()

# 4. Eski key (bitmis)
print("4. KULLANICI BITMIS KEY GIRIYOR")
eski, _ = key_uret("12345678", -365)  # 1 yil once
ok, msg = key_dogrula(eski, "12345678")
print(f"   {msg}")
print()

print("=" * 60)
print("SONUC: Bot'a key girisi yap => dogrulama basarili => bot acilir")
print("       Key baska hesapta calismaz, suresi bitince kullanilamaz")
print("=" * 60)
