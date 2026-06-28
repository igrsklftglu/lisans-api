import hmac, hashlib, base64, re, os, json, urllib.request, urllib.error
from datetime import datetime, timedelta

SECRET = "5aa34376218593058b89fd8e8cfa695e26f25980a999e98cd76c9e86cd81db8e"

API_URL = os.environ.get("LISANS_API_URL", "").rstrip("/")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "admin123")

plan_days = {"1": 30, "3": 90, "6": 180, "12": 365}
plan_lifetime = {"0": "suresiz"}

print("=" * 60)
print("          LISANS ANAHTARI URETICI")
print("=" * 60)

hesap = input("\nMusterinin MT5 Hesap No (kayit icin): ").strip()
while not hesap.isdigit() or len(hesap) < 4 or len(hesap) > 12:
    if not hesap.isdigit():
        hesap = input("Sadece rakam girin: ").strip()
    else:
        hesap = input(f"Geçersiz ({len(hesap)} hane). 4-12: ").strip()

email = input("\nMusterinin Email Adresi: ").strip()
while not re.match(r"[^@]+@[^@]+\.[^@]+", email):
    email = input("Geçerli email girin: ").strip()

plan = input("\nPlan (0=suresiz / 1/3/6/12 ay): ").strip()
while plan not in plan_days and plan not in plan_lifetime:
    plan = input("0, 1, 3, 6 veya 12 girin: ").strip()

plan_adi = "suresiz" if plan == "0" else f"{plan}month"

# Expiry key'in icine gomulur, ayni key tekrar kullanilamaz
if plan == "0":
    expiry_ymd = "00000000"
else:
    expiry_ymd = (datetime.now() + timedelta(days=plan_days[plan])).strftime("%Y%m%d")

payload = f"{email}|{plan_adi}|{expiry_ymd}"
sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
key = base64.b64encode(f"{payload}|{sig}".encode()).decode()

now = datetime.now().strftime("%Y-%m-%d %H:%M")
now_iso = datetime.now().isoformat()
bitis_str = "Süresiz" if plan == "0" else (datetime.now() + timedelta(days=plan_days.get(plan, 0))).isoformat()

print("\n" + "=" * 60)
print(f"  Hesap:    {hesap}")
print(f"  Email:    {email}")
print(f"  Plan:     {'Süresiz' if plan == '0' else f'{plan} ay ({plan_days[plan]} gün)'}")
print(f"  Bitiş:    {bitis_str}")
print(f"  Anahtar:  {key}")
print("=" * 60)

# === API KAYDI (opsiyonel) ===
if API_URL:
    try:
        data = json.dumps({"email": email, "plan": plan_adi, "hesap": hesap}).encode()
        req = urllib.request.Request(
            f"{API_URL}/api/register?token={ADMIN_TOKEN}",
            data=data,
            headers={"Content-Type": "application/json"}
        )
        resp = urllib.request.urlopen(req, timeout=10)
        result = json.loads(resp.read())
        if result.get("success"):
            print(f"[OK] API kayit basarili: {API_URL}")
        else:
            print(f"[!] API kayit basarisiz: {result.get('error', '?')}")
    except Exception as e:
        print(f"[!] API'ye kayit yapilamadi: {e}")
        print("    (Local kayit devam ediyor)")
else:
    print("[!] LISANS_API_URL tanimli degil, sadece local kayit yapildi")
    print("    Export yap: set LISANS_API_URL=https://xxx.onrender.com")

# === KAYIT DOSYASI ===
desktop = os.path.join(os.path.expanduser("~"), "Desktop")
kayit_dosya = os.path.join(desktop, "LISANS_KAYITLARI.json")

# Her key icin ayri txt
txt_dosya = os.path.join(desktop, f"LISANS_KEY_{hesap}.txt")
with open(txt_dosya, "w", encoding="utf-8") as f:
    f.write(f"Hesap: {hesap}\n")
    f.write(f"Email: {email}\n")
    f.write(f"Plan:  {'Süresiz' if plan == '0' else f'{plan} ay'}\n")
    f.write(f"Anahtar: {key}\n")
    f.write(f"Tarih: {now}\n")
print(f"\n[OK] Key dosyasi: {txt_dosya}")

# Tum kayitlarin listesi (JSON)
kayit = {
    "email": email,
    "hesap": hesap,
    "plan": plan_adi,
    "ip": "—",
    "olusturulma": now,
    "plan_bitis": bitis_str,
    "aktivasyon_tarihi": "-",
    "aktivasyon_bitis": "-",
}

kayitlar = []
if os.path.exists(kayit_dosya):
    try:
        with open(kayit_dosya, "r", encoding="utf-8") as f:
            kayitlar = json.load(f)
    except:
        kayitlar = []

kayitlar.append(kayit)
with open(kayit_dosya, "w", encoding="utf-8") as f:
    json.dump(kayitlar, f, indent=2, ensure_ascii=False)
print(f"[OK] Kayit listesi: {kayit_dosya}")

# === HTML liste (license_server klasorunde, govulu veri) ===
def _html_olustur(kayitlar, html_dosya):
    veriler = []
    for i, k in enumerate(kayitlar, 1):
        plan_gor = k.get("plan", "?").replace("month", " Ay").replace("suresiz", "Süresiz")
        veriler.append({
            "i": i, "e": k.get("email", ""), "h": k.get("hesap", ""),
            "p": plan_gor, "o": k.get("olusturulma", "-"),
            "b": k.get("plan_bitis", "-"), "a": k.get("aktivasyon_bitis", "-"),
            "ip": k.get("ip", "-"),
        })
    veri_json = json.dumps(veriler, ensure_ascii=False)
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="5"><title>Lisans Kayitlari</title>
<style>
body {{ font-family: Arial; margin: 30px; }}
table {{ border-collapse: collapse; width: 100%; }}
th {{ background: #4A9EDA; color: white; padding: 10px; text-align: left; }}
td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
tr:hover {{ background: #f0f0f0; }}
</style></head><body>
<h2>Lisans Kayitlari</h2>
<table id="tablo"></table>
<p style="color:#999;font-size:12px;margin-top:20px;">Son güncelleme: <span id="tarih">-</span></p>
<script>
const VERI = {veri_json};
function kalanHesapla(bitis) {{
    if (!bitis) return ['Aktif Edilmedi', -1];
    if (bitis === '-' || bitis === 'Süresiz') return ['Süresiz', -1];
    if (bitis.length < 8) return ['Aktif Edilmedi', -1];
    const fark = new Date(bitis) - new Date();
    if (fark <= 0) return ['<span style="color:red">Süresi Doldu</span>', 0];
    const t = Math.floor(fark / 1000);
    let g = Math.floor(t / 86400);
    const s = Math.floor((t % 86400) / 3600);
    const d = Math.floor((t % 3600) / 60);
    const sn = t % 60;
    let p = [];
    if (g >= 30) {{ p.push(Math.floor(g/30)+' ay'); g = g % 30; }}
    if (g > 0) p.push(g+' gün');
    if (s > 0) p.push(s+' saat');
    p.push(d+' dk');
    p.push(sn+' sn');
    return [p.join(' '), fark];
}}
let kalanHuccreleri = [];
function render(d) {{
    let h = '<tr><th>#</th><th>Email</th><th>Hesap</th><th>Plan</th><th>Oluşturulma</th><th>Bitiş</th><th>Kalan</th><th>IP</th></tr>';
    kalanHuccreleri = [];
    d.forEach((r, idx) => {{
        const kalan_bitis = r.a && r.a !== '-' ? r.a : null;
        const sonuc = kalanHesapla(kalan_bitis);
        const kln = sonuc[0];
        h += '<tr><td>'+r.i+'</td><td>'+r.e+'</td><td>'+r.h+'</td><td>'+r.p+'</td><td>'+r.o+'</td><td>'+(r.b||'-').substring(0,10)+'</td><td id="k'+idx+'">'+kln+'</td><td>'+r.ip+'</td></tr>';
        if (kalan_bitis && kalan_bitis.length >= 8 && kalan_bitis !== 'Süresiz') {{
            const fark = new Date(kalan_bitis) - new Date();
            if (fark > 0) kalanHuccreleri.push({{ idx: idx, bitis: kalan_bitis }});
        }}
    }});
    document.getElementById('tablo').innerHTML = h;
    document.getElementById('tarih').textContent = new Date().toLocaleString('tr-TR');
}}
render(VERI);
if (kalanHuccreleri.length > 0) {{
    setInterval(() => {{
        kalanHuccreleri.forEach(r => {{
            const h = document.getElementById('k'+r.idx);
            if (h) h.textContent = kalanHesapla(r.bitis)[0];
        }});
    }}, 1000);
}}
</script></body></html>"""
    with open(html_dosya, "w", encoding="utf-8") as f:
        f.write(html)

license_dir = os.path.dirname(os.path.abspath(__file__))
html_dosya = os.path.join(license_dir, "LISANS_KAYITLARI.html")
_html_olustur(kayitlar, html_dosya)
print(f"[OK] HTML liste: {html_dosya}")

print(f"\nToplam kayit: {len(kayitlar)}")
input("\nCikmak icin Enter'a basin...")
