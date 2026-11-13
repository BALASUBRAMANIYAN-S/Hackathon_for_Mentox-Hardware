# NetSentinel: Real-Time Network Scanner, Rogue IP Detector & Firewall Blocker

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](file:///c:/Users/balal/Desktop/Mentrox/app.py)
[![MySQL](https://img.shields.io/badge/Database-MySQL80-orange.svg)](file:///c:/Users/balal/Desktop/Mentrox/db.py)
[![Firewall](https://img.shields.io/badge/Firewall-Windows%20Defender%20Blocker-red.svg)](file:///c:/Users/balal/Desktop/Mentrox/blocker.py)
[![Email Alerts](https://img.shields.io/badge/Alerts-SMTP%20App%20Password-green.svg)](file:///c:/Users/balal/Desktop/Mentrox/notifier.py)

---

## 1. ப்ராஜெக்ட் விளக்கம் (What this Project Does)

**NetSentinel** என்பது உங்கள் லோக்கல் நெட்வொர்க்கில் (Wi-Fi / Ethernet) இணையும் அனைத்து சாதனங்களையும் உடனுக்குடன் ஸ்கேன் செய்து பாதுகாக்கும் ஒரு **நெட்வொர்க் பாதுகாப்பு சிஸ்டம்**:

1. **Network Scanner:** நெட்வொர்க்கில் உள்ள அனைத்து சாதனங்களையும் (IP, MAC Address, Device Name) தானாகக் கண்டுபிடித்து டேஷ்போர்டில் பட்டியலிடும்.
2. **MySQL Database Whitelist:** அனுமதிக்கப்பட்ட (Authorized) IP முகவரிகளை MySQL டேட்டாபேஸில் (`authorized_ips`) சேமித்து வைக்கும்.
3. **Continuous Background Monitoring:** நெட்வொர்க்கை இடைவிடாமல் பின்னணியில் ஸ்கேன் செய்து கொண்டிருக்கும்.
4. **Rogue IP Warning:** MySQL-ல் இல்லாத எந்தவொரு புதிய IP நெட்வொர்க்கில் நுழைந்தாலும், உடனடியாக **WARNING ALERT** அடிக்கும்! (அனுமதிக்கப்பட்ட IP என்றால் எந்த வார்னிங்கும் வராது).
5. **Instant Email Alerts:** அனுமதி இல்லாத IP கண்டுபிடிக்கப்பட்டால், உங்கள் ஈமெயிலுக்கு உடனடியாக சாதனத்தின் முழு விபரங்களுடன் (IP, MAC, Hostname, Time) எச்சரிக்கை மெயில் அனுப்பும்.
6. **Windows Firewall IP Blocker:** டேஷ்போர்டில் ஒரே கிளிக்கில் அந்த மர்ம IP-யை விண்டோஸ் ஃபயர்வால் வழியாக **முழுமையாக பிளாக் (Block / Isolate)** செய்துவிடலாம்!

---

## 2. முக்கிய அமைப்புகள் (`.env` Configuration)

அனைத்து பாஸ்வேர்டுகள், கீகள் மற்றும் செட்டிங்குகள் **[`.env`](file:///c:/Users/balal/Desktop/Mentrox/.env)** ஃபைலில் பாதுகாப்பாக வைக்கப்பட்டுள்ளன:

```env
# --- MySQL Database Configuration ---
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=root
DB_NAME=net_sentinel_db

# --- Email Alert Settings (Gmail App Password) ---
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=True
SENDER_EMAIL=your_email@gmail.com
SENDER_APP_PASSWORD=xxxx xxxx xxxx xxxx
ALERT_RECIPIENT_EMAIL=your_email@gmail.com
ENABLE_EMAIL_ALERTS=True

# --- Scanner Settings ---
SCAN_INTERVAL_SECONDS=20
AUTO_DETECT_SUBNET=True
AUTO_BLOCK_ROGUE_IPS=False
WEB_PORT=5000
```

---

## 3. ஈமெயில் ஆப் பாஸ்வேர்ட் அமைப்பது எப்படி? (How to set Gmail App Password)

ஜிமெயில் மூலம் அலர்ட் மெயில் வர வைக்க:
1. உங்கள் **Google Account**-ல் `Security` பக்கத்திற்கு செல்லவும்.
2. **2-Step Verification** ஆன் செய்யப்பட்டுள்ளதா என உறுதிப்படுத்தவும்.
3. மேலே உள்ள தேடல் பட்டியில் **"App Passwords"** என தேடவும் (நேரடி இணைப்பு: `https://myaccount.google.com/apppasswords`).
4. ஆப் பெயர்: `NetSentinel` என கொடுத்து **Create** கொடுக்கவும்.
5. கூகுள் தரும் **16 எழுத்து பாஸ்வேர்டை (16-character code)** காப்பி செய்யவும்.
6. [`.env`](file:///c:/Users/balal/Desktop/Mentrox/.env) ஃபைலை திறந்து:
   ```env
   SENDER_EMAIL=your_real_email@gmail.com
   SENDER_APP_PASSWORD=abcd efgh ijkl mnop
   ALERT_RECIPIENT_EMAIL=your_real_email@gmail.com
   ```
   என்று மாற்றி சேமிக்கவும்.

---

## 4. அப்ளிகேஷனை இயக்குவது எப்படி? (How to Run)

டெர்மினலில் ஒரே ஒரு கமாண்ட் கொடுக்கவும்:

```bash
py app.py
```

வெற்றி செய்தி வந்ததும் உங்கள் பிரவுசரில் திறக்கவும்:
👉 **[http://localhost:5000](http://localhost:5000)**

---

## 5. டேஷ்போர்டு அம்சங்கள் (Dashboard Features)

* **Top Metric Bar:** மொத்த சாதனங்கள், MySQL-ல் அனுமதிக்கப்பட்ட சாதனங்கள், வார்னிங் சாதனம் எண்ணிக்கை, பிளாக் செய்யப்பட்ட IP-கள்.
* **Critical Warning Alert Feed:** அங்கீகரிக்கப்படாத சாதனங்கள் சிவப்பாக ஒளிரும் அலர்ட் கார்டுகளாகத் தோன்றும். அதில்:
  * **[✔ Authorize IP]** கிளிக் செய்தால் அந்த IP உடனடியாக MySQL-ல் பதிவாகி வார்னிங் நீங்கிவிடும்.
  * **[🚫 Block IP]** கிளிக் செய்தால் அந்த IP உடனடியாக விண்டோஸ் ஃபயர்வாலில் பிளாக் செய்யப்பட்டுவிடும்!
* **Live Network Inventory:** அனைத்து சாதனங்களின் IP, MAC, ஹோஸ்ட் நேம் மற்றும் ஸ்டேட்டஸ் அடங்கிய அட்டவணை.
* **Scan Network Now:** தேவைப்படும்போது உடனடியாக ஒரு முழு நெட்வொர்க் ஸ்கேன் செய்யும் பட்டன்.
* **MySQL Whitelist Manager:** அனுமதிக்கப்பட்ட IP-களை நேரடியாக சேர்த்தல் மற்றும் நீக்குதல்.
* **Test Email Button:** ஈமெயில் செட்டிங்ஸ் சரியாக வேலை செய்கிறதா என்று சோதிக்க உதவும் பட்டன்.

---

## 6. கோப்புகள் மற்றும் கட்டமைப்பு (File Architecture)

```
c:\Users\balal\Desktop\Mentrox\
├── .env                      # Database, Email Password, and Scanner Configuration
├── .env.example              # Template reference for environment variables
├── db.py                     # MySQL Database manager (authorized whitelist, alerts, devices)
├── network_scanner.py        # High-speed network scanner (ARP table + ICMP + Hostnames)
├── blocker.py                # Windows Firewall IP Blocker / Unblocker engine
├── notifier.py               # SMTP HTML Email alert dispatcher with App Password support
├── monitor.py                # Background continuous monitoring and automatic alerting loop
├── app.py                    # Web Dashboard server & REST API
└── static/
    ├── index.html            # Cyber-defense dark mode UI
    ├── style.css             # Responsive styling and glowing alert badges
    └── app.js                # Dynamic AJAX polling, real-time filters, and instant action handlers
```
