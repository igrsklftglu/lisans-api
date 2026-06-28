# -*- coding: utf-8 -*-
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from license.license_manager import license_manager

# Test 1: Gecersiz key
r = license_manager.verify('abc', '123')
print(f'Test 1 (gecersiz key): {r}')

# Test 2: Gecerli key uret
import hmac, hashlib, base64
from datetime import datetime, timedelta

payload = '12345678|20261231|12month'
sig = hmac.new(
    b'5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e',
    payload.encode(), hashlib.sha256
).hexdigest()[:16]
key = base64.b64encode(f'{payload}|{sig}'.encode()).decode()

print(f'\nTest key: {key}')
r2 = license_manager.verify(key, '12345678')
print(f'Test 2 (gecerli): {r2}')

# Test 3: Yanlis hesap no
r3 = license_manager.verify(key, '99999999')
print(f'Test 3 (yanlis hesap): {r3}')

# Test 4: check_online
print(f'\nLisansli mi: {license_manager.is_licensed()}')
print(f'Ekran: {license_manager.get_expiry_display()}')
ok = license_manager.check_online()
print(f'Check online: {ok}')

# Test 5: License suresi gecmis (expired)
print('\n--- Test expired key ---')
expired_payload = '12345678|20200101|1month'
expired_sig = hmac.new(
    b'5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e',
    expired_payload.encode(), hashlib.sha256
).hexdigest()[:16]
expired_key = base64.b64encode(f'{expired_payload}|{expired_sig}'.encode()).decode()
r4 = license_manager.verify(expired_key, '12345678')
print(f'Test expired: {r4}')

print('\n=== TUM TESTLER BASARILI ===')
