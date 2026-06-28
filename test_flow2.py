import sys, os, base64, hmac, hashlib
sys.path.insert(0, r'C:\Users\Administrator\Desktop\MT5 GOLD BOT\src')
from license.license_manager import license_manager

SECRET = "5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e"

# Gecerli key (XM broker)
payload = "XMGlobal-MT5 9|12345678|20261231|1month"
sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
key = base64.b64encode(f"{payload}|{sig}".encode()).decode()
print(f"Key: {key}")

r = license_manager.verify(key, "12345678", "XMGlobal-MT5 9")
print(f"Dogru broker + hesap: {r.get('valid')} - {r.get('reason', 'OK')}")

r2 = license_manager.verify(key, "12345678", "YanlisBroker")
print(f"Yanlis broker: {r2.get('valid')} - {r2.get('reason')}")

r3 = license_manager.verify(key, "99999999", "XMGlobal-MT5 9")
print(f"Yanlis hesap: {r3.get('valid')} - {r3.get('reason')}")
