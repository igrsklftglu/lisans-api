# -*- coding: utf-8 -*-
"""Bir kereye mahsus anahtar cifti uretir (Ed25519).

Cikti:
  - LICENSE_PRIVATE_KEY  (base64)  -> SADECE sunucuda (Render env). GIZLI!
  - LICENSE_PUBLIC_KEY   (base64)  -> istemciye gomulur (license_manager.py)

Ayrica yerel test icin signing_keys.local.json yazar. BU DOSYAYI
GITHUB'A YUKLEMEYIN / PAYLASMAYIN.
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import signing

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def main():
    sk, pk = signing.generate_keypair()
    sk_b64 = base64.b64encode(sk).decode()
    pk_b64 = base64.b64encode(pk).decode()

    out = {
        "LICENSE_PRIVATE_KEY": sk_b64,
        "LICENSE_PUBLIC_KEY": pk_b64,
    }
    local_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signing_keys.local.json")
    with open(local_file, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print("=" * 64)
    print("  ED25519 ANAHTAR CIFTI URETILDI")
    print("=" * 64)
    print("\n[GIZLI] LICENSE_PRIVATE_KEY  (Render env'e ekle, KIMSEYE VERME):\n")
    print(sk_b64)
    print("\n[ACIK]  LICENSE_PUBLIC_KEY   (istemciye gomulur):\n")
    print(pk_b64)
    print("\n" + "=" * 64)
    print(f"Yerel kayit: {local_file}  (GITHUB'A YUKLEME!)")
    print("=" * 64)


if __name__ == "__main__":
    main()
