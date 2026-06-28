import sys, os
sys.path.insert(0, r'C:\Users\Administrator\Desktop\MT5 GOLD BOT\src')
from license.license_manager import license_manager

# Yanlis sifre dene
r = license_manager.verify("abc", "test@email.com")
print(f"Gecersiz key: {r.get('valid')} - {r.get('reason')}")

# Gecerli key dene
import base64, hmac, hashlib
SECRET = "5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e"
payload = "musteri@email.com|1month"
sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
key = base64.b64encode(f"{payload}|{sig}".encode()).decode()

r2 = license_manager.verify(key, "musteri@email.com")
print(f"Gecerli key: {r2.get('valid')} - {r2.get('reason', 'OK')} kalan: {r2.get('remaining_days')} gun")
