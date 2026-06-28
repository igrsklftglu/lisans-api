import sys, os, base64, hmac, hashlib
sys.path.insert(0, r'C:\Users\Administrator\Desktop\MT5 GOLD BOT\src')
from license.license_manager import license_manager

SECRET = "5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e"

# Key'de "XMGlobal" yaziyor (sade isim)
payload = "XMGlobal|12345678|20261231|1month"
sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
key = base64.b64encode(f"{payload}|{sig}".encode()).decode()
print(f"Key (broker=XMGlobal): {key}")

# Kullanici "XMGlobal-MT5 9" yazarsa (tam server adiyla) -> eslesmeli
r = license_manager.verify(key, "12345678", "XMGlobal-MT5 9")
print(f"XMGlobal-MT5 9: {r.get('valid')} - {r.get('reason', 'OK')}")

# Kullanici "xmglobal" yazarsa (kucuk harf) -> eslesmeli
r2 = license_manager.verify(key, "12345678", "xmglobal")
print(f"xmglobal: {r2.get('valid')} - {r2.get('reason', 'OK')}")

# Kullanici "FTMO" yazarsa -> eslesmemeli
r3 = license_manager.verify(key, "12345678", "FTMO")
print(f"FTMO: {r3.get('valid')} - {r3.get('reason')}")

# Key'de "XMGlobal-MT5 9" yaziyor (tam server) -> "XMGlobal" ile eslesmeli
payload2 = "XMGlobal-MT5 9|12345678|20261231|1month"
sig2 = hmac.new(SECRET.encode(), payload2.encode(), hashlib.sha256).hexdigest()[:16]
key2 = base64.b64encode(f"{payload2}|{sig2}".encode()).decode()
r4 = license_manager.verify(key2, "12345678", "XMGlobal")
print(f"\nKey'de XMGlobal-MT5 9, kullanici XMGlobal: {r4.get('valid')} - {r4.get('reason', 'OK')}")
