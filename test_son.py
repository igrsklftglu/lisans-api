import sys, base64, hmac, hashlib
sys.path.insert(0, r'C:\Users\Administrator\Desktop\MT5 GOLD BOT\src')
from license.license_manager import license_manager

SECRET = "5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e"

# Key'de bitis yok, sadece email + plan
payload = "musteri@email.com|1month"
sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
key = base64.b64encode(f"{payload}|{sig}".encode()).decode()
print(f"Key: {key}")
print("Key'de bitis yok, sadece email|plan|imza")

r = license_manager.verify(key, "musteri@email.com")
print(f"\nDogru: {r.get('valid')}")
print(f"Sure: {r.get('remaining_days')} gun")
print(f"Bitis: {r.get('expiry')}")

# Simdi kontrol et
print(f"\nLisansli mi: {license_manager.is_licensed()}")
print(f"Ekran: {license_manager.get_expiry_display()}")
