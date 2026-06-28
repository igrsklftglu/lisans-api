import sys, os, base64, hmac, hashlib, json
sys.path.insert(0, r'C:\Users\Administrator\Desktop\MT5 GOLD BOT\src')
from license.license_manager import license_manager

SECRET = "5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e"

payload = "test@email.com|1month"
sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
key = base64.b64encode(f"{payload}|{sig}".encode()).decode()

r = license_manager.verify(key, "test@email.com")
print(f"Aktivasyon: {r.get('valid')}")

# license dosyasini oku
data = license_manager.license_data
print(f"Email: {data.get('email')}")
print(f"IP: {data.get('activation_ip')}")
print(f"Tarih: {data.get('activated_at')}")
print(f"Suresi: {data.get('expiry')}")
