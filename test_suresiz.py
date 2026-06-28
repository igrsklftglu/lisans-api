import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\MT5 GOLD BOT\src')
from license.license_manager import license_manager

# Suresiz key dene
key = 'MTIzNDU2Nzh8MjA5OTEyMzF8c3VyZXNpenw4MmMxYWE1MWJkNDYyNjMy'
r = license_manager.verify(key, '12345678')
print(f'Gecerli: {r.get("valid")}')
print(f'Remaining days: {r.get("remaining_days")}')
print(f'Ekran: {license_manager.get_expiry_display()}')
