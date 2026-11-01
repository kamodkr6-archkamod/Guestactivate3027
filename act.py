#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KAMOD DEVILS WILL RISE — Standalone Activator (IND Fixed + Proxy + DataDome)
"""

import os, sys, json, time, random, hashlib, hmac, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import requests
from requests.adapters import HTTPAdapter
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── CONSTANTS ──
APP_ID = 100067
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
CLIENT_VERSION = "2.132.4"
CLIENT_VERSION_CODE = "2019121227"
RELEASE_VERSION = "OB55"
MSDK_VERSION = "4.0.44"
DATADOME_SDK_URL = "https://api-sdk.datadome.co/sdk/"
DATADOME_KEY = "AE3F04AD3F0D3A462481A337485081"
DATADOME_VERSION = "1.13.9"

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# ── REGIONS (FIXED) ──
REGIONS = {
    "IND": {
        "oauth_register": "https://connect.garena.com/api/v2/oauth/guest:register",
        "oauth_token":    "https://connect.garena.com/api/v2/oauth/guest/token:grant",
        "login_host":  "loginbp.ggblueshark.com",
        "client_host": "client.ind.freefiremobile.com",
        "gateway": "IND", "lang": "hi", "choose_code": "IND",
        "isps": ["Jio 5G", "Airtel", "Vi India", "BSNL Broadband"],
        "ip_subnets": ["49.36", "49.32", "27.59", "106.193", "115.99"],
        "cities": [("Mumbai","MH"), ("New Delhi","DL"), ("Bangalore","KA")]
    },
    "BD": {
        "oauth_register": "https://ffmconnect.ppmainecoonghj.com/api/v2/oauth/guest:register",
        "oauth_token":    "https://ffmconnect.ppmainecoonghj.com/api/v2/oauth/guest/token:grant",
        "login_host":  "loginbp.ppmainecoonghj.com",
        "client_host": "clientbp.ppmainecoonghj.com",
        "gateway": "SG", "lang": "en", "choose_code": "BD",
        "isps": ["Grameenphone", "Robi", "Banglalink", "Link3"],
        "ip_subnets": ["103.157", "103.205", "27.147", "118.179"],
        "cities": [("Dhaka","C"), ("Chittagong","B"), ("Sylhet","E")]
    },
    "PK": {
        "oauth_register": "https://connect.garena.com/api/v2/oauth/guest:register",
        "oauth_token":    "https://connect.garena.com/api/v2/oauth/guest/token:grant",
        "login_host":  "loginbp.ggblueshark.com",
        "client_host": "clientbp.ppmainecoonghj.com",
        "gateway": "SG", "lang": "ur", "choose_code": "PK",
        "isps": ["Jazz", "Zong 4G", "Telenor PK", "PTCL"],
        "ip_subnets": ["39.40", "39.50", "111.68", "182.180"],
        "cities": [("Karachi","SD"), ("Lahore","PB"), ("Islamabad","IS")]
    },
    "TW": {
        "oauth_register": "https://connect.garena.com/api/v2/oauth/guest:register",
        "oauth_token":    "https://connect.garena.com/api/v2/oauth/guest/token:grant",
        "login_host":  "loginbp.ggblueshark.com",
        "client_host": "clientbp.ppmainecoonghj.com",
        "gateway": "SG", "lang": "zh-TW", "choose_code": "TW",
        "isps": ["Chunghwa Telecom", "Taiwan Mobile", "FarEasTone"],
        "ip_subnets": ["114.32", "211.20", "61.216"],
        "cities": [("Taipei","TPE"), ("Kaohsiung","KHH")]
    },
}

DEVICE_MODELS = [
    {"brand": "Google", "model": "Google Pixel 5"},
    {"brand": "Samsung", "model": "samsung SM-G981B"},
    {"brand": "Xiaomi", "model": "Xiaomi Redmi Note 9"},
    {"brand": "OnePlus", "model": "OnePlus Nord"},
    {"brand": "Realme", "model": "realme RMX2001"},
]

# ── PROTOBUF ──
def write_varint(value):
    out = []
    while value > 127:
        out.append((value & 0x7F) | 0x80); value >>= 7
    out.append(value); return bytes(out)

def assemble_proto(fields):
    data = bytearray()
    for k in sorted(fields.keys()):
        v = fields[k]
        if isinstance(v, int):
            data.extend(write_varint((k << 3) | 0) + write_varint(v))
        elif isinstance(v, str):
            b = v.encode("utf-8")
            data.extend(write_varint((k << 3) | 2) + write_varint(len(b)) + b)
        elif isinstance(v, (bytes, bytearray)):
            data.extend(write_varint((k << 3) | 2) + write_varint(len(v)) + v)
    return bytes(data)

def read_varint(data, offset):
    r, s = 0, 0
    while True:
        b = data[offset]; offset += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80): break
        s += 7
    return r, offset

def parse_proto(data):
    out = {}
    off = 0
    while off < len(data):
        try: tag, off = read_varint(data, off)
        except: break
        f = tag >> 3; w = tag & 0x7
        if f == 0: break
        try:
            if w == 0:
                v, off = read_varint(data, off); out[f] = v
            elif w == 2:
                ln, off = read_varint(data, off)
                val = data[off:off+ln]; off += ln
                try: out[f] = val.decode("utf-8")
                except: out[f] = val.hex()
            else: break
        except: break
    return out

# ── CRYPTO ──
def aes_encrypt(plain):
    if not isinstance(plain, (bytes, bytearray)): plain = plain.encode("utf-8")
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(plain, AES.block_size))

def aes_decrypt(ciphertext):
    if not ciphertext or len(ciphertext) % 16 != 0: return ciphertext
    try:
        try: return unpad(AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(ciphertext), AES.block_size)
        except ValueError: return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(ciphertext)
    except: return ciphertext

def create_session(proxy=None):
    s = requests.Session()
    s.verify = False
    adapter = HTTPAdapter(pool_connections=20, pool_maxsize=50, max_retries=0)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    if proxy: s.proxies = {"http": proxy, "https": proxy}
    return s

# ── PROXY LOADER ──
def get_proxy(region):
    if not os.path.exists("proxies.txt"): return None
    pool = []
    with open("proxies.txt", "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith(f"{region}:"):
                pool.append(line.split(":", 1)[1])
    return f"http://{random.choice(pool)}" if pool else None

# ── DATADOME SDK ──
def fetch_datadome_cookie(session, device_info, target_url):
    try:
        now_ms = int(time.time() * 1000)
        brand = device_info.get("brand", "Google")
        model = device_info.get("model", "Google Pixel 5")
        mdl = model.split(" ")[-1] if " " in model else model
        payload = {
            "cid": "", "ddv": DATADOME_VERSION, "ddvc": MSDK_VERSION, "ddk": DATADOME_KEY,
            "request": target_url, "os": "Android", "osr": "10", "osn": "Q", "osv": "29",
            "ua": f"GarenaMSDK/{MSDK_VERSION}({mdl} ;Android 10;en;US;app 1.132.1 2019121227;)",
            "screen_x": 1080, "screen_y": 2400, "screen_d": 420,
            "events": json.dumps([{"id": 1, "message": "response validation", "source": "sdk", "date": now_ms}]),
            "camera": json.dumps({"auth": "false", "info": "{}"}),
            "mdl": mdl, "prd": mdl.lower(), "mnf": brand, "dev": mdl.lower(), "hrd": "qcom",
            "fgp": f"{brand}/{mdl}/{mdl}:10/QP1A.190711.020/6009276:user/release-keys",
            "tgs": "release-keys", "inte": "android-java-okhttp"
        }
        headers = {"content-type": "application/x-www-form-urlencoded", "user-agent": "okhttp/4.12.0", "accept-encoding": "gzip"}
        r = session.post(DATADOME_SDK_URL, data=payload, headers=headers, timeout=8)
        if r.status_code == 200:
            raw_cookie = r.json().get("cookie", "")
            if "datadome=" in raw_cookie:
                cookie_val = raw_cookie.split("datadome=")[1].split(";")[0].strip()
                for dom in [".ppmainecoonghj.com", ".ggblueshark.com", "connect.garena.com"]:
                    session.cookies.set("datadome", cookie_val, domain=dom)
                return cookie_val
    except: pass
    return None

# ── DEVICE-ID GENERATE ──
def generate_device_id(session, device_info, dd_cookie=None, region_host="ffmmsdk.ppmainecoonghj.com"):
    try:
        brand = device_info.get("brand", "Google")
        model = device_info.get("model", "Google Pixel 5")
        mdl = model.split(" ")[-1] if " " in model else model
        url = f"https://{region_host}/device/api/v1/android/device-id:generate"
        body_obj = {"app_id": APP_ID, "data": {
            "ad_aaid": str(uuid.uuid4()),
            "android_id": hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:16],
            "android_version_release": "10", "android_version_sdk": "29",
            "brand": brand, "build_date": "1647401473000",
            "build_display": f"{mdl} release-keys", "build_id": "QP1A.190711.020",
            "cpu_abis": "arm64-v8a,armeabi-v7a,armeabi", "drm_id": "", "drm_vendor": "",
            "fingerprint": f"{brand}/{mdl}/{mdl}:10/QP1A.190711.020/6009276:user/release-keys",
            "gcbooster_uuid": "", "hardware": "qcom", "imei": "", "model": mdl,
            "key_mqs_uuid": "", "product_name": mdl.lower(),
            "random_uuid": str(uuid.uuid4()), "soc_manufacturer": "", "soc_model": ""
        }}
        body = json.dumps(body_obj, separators=(",", ":"))
        sig = hmac.new(CLIENT_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        headers = {
            "User-Agent": f"GarenaMSDK/{MSDK_VERSION}({mdl} ;Android 10;en;US;app 1.132.1 2019121227;)",
            "Authorization": f"Signature {sig}",
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "Host": region_host,
        }
        if dd_cookie: headers["Cookie"] = f"datadome={dd_cookie}"
        r = session.post(url, data=body, headers=headers, timeout=10)
        if r.status_code == 200:
            d = r.json()
            if d.get("code") == 0 and "data" in d:
                return d["data"].get("device_id")
    except: pass
    return None

# ── AUTH ──
def get_token(session, uid, password, region_code, device_info, device_id=""):
    reg = REGIONS[region_code]
    tok_url = reg["oauth_token"]
    model = device_info["model"].split(" ")[-1] if " " in device_info["model"] else device_info["model"]
    payload = {
        "client_id": APP_ID, "client_secret": CLIENT_SECRET, "client_type": 2,
        "device_id": device_id or "", "password": password,
        "response_type": "token", "uid": int(uid)
    }
    body = json.dumps(payload, separators=(",", ":"))
    headers = {
        "User-Agent": f"GarenaMSDK/{MSDK_VERSION}({model} ;Android 10;en;US;app 1.132.1 2019121227;)",
        "Content-Type": "application/json; charset=utf-8",
        "Host": tok_url.split("/")[2],
    }
    try:
        r = session.post(tok_url, data=body, headers=headers, timeout=12)
        if r.status_code == 200:
            d = r.json()
            if d.get("code") == 0 and "data" in d:
                return d["data"].get("access_token"), d["data"].get("open_id")
            print(f"[{uid}] Token error body: {d}")
        else:
            print(f"[{uid}] Token HTTP {r.status_code}: {r.text[:200]}")
    except Exception as e: print(f"[{uid}] Token Exception: {e}")
    return None, None

def send_major_login(session, access_token, open_id, region_code, device_info):
    reg = REGIONS[region_code]
    host = reg["login_host"]
    city, prov = random.choice(reg["cities"])
    isp = random.choice(reg["isps"])
    subnet = random.choice(reg["ip_subnets"])
    client_ip = f"{subnet}.{random.randint(1,250)}.{random.randint(1,250)}"
    model = device_info["model"]

    fields = {
        3: time.strftime("%Y-%m-%d %H:%M:%S"), 4: "free fire", 5: 2, 7: CLIENT_VERSION,
        8: "Android OS 10 / API-29 (QP1A.190711.020/6009276:user/release-keys)",
        9: "Handheld", 10: isp, 11: "WIFI", 12: 1280, 13: 720, 14: "320",
        15: "ARM64 FP ASIMD AES | 2803 | 8", 16: 3968,
        17: "Adreno (TM) 610",
        18: "OpenGL ES 3.2 V@0615.91 (GIT@a63fb93269, I16b8254a37, 1724729505)",
        19: f"Google|{uuid.uuid4()}", 20: client_ip, 21: reg["lang"],
        22: open_id, 23: "4", 24: "Handheld", 25: model, 26: reg["gateway"],
        29: access_token, 30: 1, 41: isp, 42: "WIFI",
        57: "1ac4b80ecf0478a44203bf8fac6120f5",
        60: 231923, 61: 80462, 62: 2048, 63: 804, 64: 80462, 65: 231923,
        66: 80462, 67: 231923, 70: 4, 73: 3,
        74: "/data/app/com.dts.freefireth-iFL8hy300LRo3a_upuIkpg==/lib/arm64",
        76: 1, 77: "066a589fa3f5658377634fe7b1d88556|/data/app/com.dts.freefireth-iFL8hy300LRo3a_upuIkpg==/base.apk",
        78: 6, 79: 2, 81: "64", 83: str(CLIENT_VERSION_CODE), 85: 3, 86: "OpenGLES2",
        87: 1023, 88: 4, 90: city, 91: prov, 92: 42395, 93: "3rd_party",
        94: "KqsHTzMTWHVzH/5lwGUk2Va1pKh9yDfcKW2DuWtz+qvGa1arQRPk9ejxtYcLmWCPhsgW22Y82GnjjPsizWtcrXk17Kmu1Pw4KRJChgP0YbQNufK+3jgY9ltOm/9Z00xX/9OWAA==",
        96: '{"cur_rate":null,"support_etc2":false}', 97: 1, 99: "4", 100: "4",
        102: b"BT\x10\x15\x05\x0e\\\x043", 104: 13939, 105: 1,
        106: "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a",
        107: "1.9393e7b8e53e8aeb"
    }
    encrypted = aes_encrypt(assemble_proto(fields))
    headers = {
        "Host": host,
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*", "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(int(time.time())),
        "Authorization": "Bearer", "X-GA": "v1 1",
        "ReleaseVersion": RELEASE_VERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
    }
    try:
        r = session.post(f"https://{host}/MajorLogin", data=encrypted, headers=headers, timeout=20)
        print(f"[MajorLogin] HTTP {r.status_code}, len={len(r.content)}")
        if r.status_code != 200:
            print(f"[MajorLogin] body: {r.text[:300]}")
            return None
        raw = r.content
        # Parse order: plaintext first, then decrypt, then skip 64
        for buf in (raw, aes_decrypt(raw), raw[64:] if len(raw) > 64 else b""):
            if not buf: continue
            try:
                p = parse_proto(buf)
                jwt = p.get(8)
                if isinstance(jwt, bytes):
                    try: jwt = jwt.decode("utf-8", "ignore")
                    except: jwt = ""
                if isinstance(jwt, str) and jwt.startswith("eyJ") and jwt.count(".") == 2:
                    return jwt
            except: pass
        print(f"[MajorLogin] No JWT in response (raw hex: {raw[:64].hex()})")
    except Exception as e:
        print(f"[MajorLogin] Exception: {e}")
    return None

def get_login_data(session, jwt, open_id, region_code, device_info):
    reg = REGIONS[region_code]
    host = reg["client_host"]
    city, prov = random.choice(reg["cities"])
    isp = random.choice(reg["isps"])
    subnet = random.choice(reg["ip_subnets"])
    client_ip = f"{subnet}.{random.randint(1,250)}.{random.randint(1,250)}"

    fields = {
        3: time.strftime("%Y-%m-%d %H:%M:%S"), 4: "free fire", 5: 2, 7: CLIENT_VERSION,
        8: "Android OS 10 / API-29 (QP1A.190711.020/6009276:user/release-keys)",
        9: "Handheld", 10: isp, 11: "WIFI", 12: 1280, 13: 720, 14: "320",
        15: "ARM64 FP ASIMD AES | 2803 | 8", 16: 3968, 17: "Adreno (TM) 610",
        18: "OpenGL ES 3.2 V@0615.91 (GIT@a63fb93269, I16b8254a37, 1724729505)",
        19: f"Google|{uuid.uuid4()}", 20: client_ip, 21: reg["lang"],
        22: open_id, 23: "4", 24: "Handheld", 25: device_info["model"],
        26: reg["gateway"], 29: jwt, 30: 1, 41: isp, 42: "WIFI",
        57: "1ac4b80ecf0478a44203bf8fac6120f5",
        60: 231923, 61: 80462, 62: 2048, 63: 804, 64: 80462, 65: 231923,
        66: 80462, 67: 231923, 70: 4, 73: 3,
        74: "/data/app/com.dts.freefireth-iFL8hy300LRo3a_upuIkpg==/lib/arm64",
        76: 1, 77: "066a589fa3f5658377634fe7b1d88556|/data/app/com.dts.freefireth-iFL8hy300LRo3a_upuIkpg==/base.apk",
        78: 6, 79: 2, 81: "64", 83: str(CLIENT_VERSION_CODE), 85: 3, 86: "OpenGLES2",
        87: 1023, 88: 4, 90: city, 91: prov, 92: 42395, 93: "3rd_party",
        94: "KqsHTzMTWHVzH/5lwGUk2Va1pKh9yDfcKW2DuWtz+qvGa1arQRPk9ejxtYcLmWCPhsgW22Y82GnjjPsizWtcrXk17Kmu1Pw4KRJChgP0YbQNufK+3jgY9ltOm/9Z00xX/9OWAA==",
        96: '{"cur_rate":null,"support_etc2":false}', 97: 1, 99: "0", 100: "4",
        102: b"BT\x10\x15\x05\x0e\\\x043", 104: 13939, 105: 1,
        106: "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a",
        107: "1.9393e7b8e53e8aeb"
    }
    encrypted = aes_encrypt(assemble_proto(fields))
    headers = {
        "Host": host,
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*", "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(int(time.time())),
        "Authorization": f"Bearer {jwt}", "X-GA": "v1 1",
        "ReleaseVersion": RELEASE_VERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
    }
    try:
        r = session.post(f"https://{host}/GetLoginData", data=encrypted, headers=headers, timeout=15)
        print(f"[GetLoginData] HTTP {r.status_code}")
        return r.status_code == 200
    except Exception as e:
        print(f"[GetLoginData] Exception: {e}")
        return False

def equip_homer(session, jwt, region_code, device_info):
    reg = REGIONS[region_code]
    host = reg["client_host"]
    base_headers = {
        "Host": host,
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*", "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(int(time.time())),
        "Authorization": f"Bearer {jwt}", "X-GA": "v1 1",
        "ReleaseVersion": RELEASE_VERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
    }
    def call_ep(ep, payload=b""):
        raw = aes_encrypt(assemble_proto(payload) if isinstance(payload, dict) else payload)
        h = dict(base_headers); h["X-GA-SV"] = str(int(time.time()))
        try: return session.post(f"https://{host}/{ep}", data=raw, headers=h, timeout=10).status_code == 200
        except: return False

    r1 = call_ep("GiveAccountNewbieRoles", {1: 3})
    time.sleep(0.05)
    r2 = call_ep("SelectPresetLoadout", bytes.fromhex(
        "121b0887cbd1301204000102031a08c205822bc6258a20220400000000322d0a2b08011087cbd130"
        "1a0310c2051a05080110822b1a05080210c6251a050803108a20320850524553455420315801"
    ))
    return r1 and r2

# ── MAIN ──
def activate_account(uid, password, region_code):
    if region_code not in REGIONS:
        return {"success": False, "error": f"Unsupported region: {region_code}"}
    device_info = random.choice(DEVICE_MODELS)
    proxy = get_proxy(region_code)
    session = create_session(proxy=proxy)
    reg = REGIONS[region_code]

    print(f"[{uid}] Region={region_code} Proxy={proxy or 'DIRECT'} Device={device_info['model']}")

    # 1. DataDome
    dd = fetch_datadome_cookie(session, device_info, reg["oauth_token"])

    # 2. Device-ID
    dev_host = "ffmmsdk.ppmainecoonghj.com" if region_code == "BD" else "ffmmsdk.ppmainecoonghj.com"
    device_id = generate_device_id(session, device_info, dd, region_host=dev_host)

    # 3. Token
    at, oi = get_token(session, uid, password, region_code, device_info, device_id or "")
    if not at: return {"success": False, "error": "Token Grant Failed (wrong pass / IP blocked / rate-limited)"}

    # 4. Major Login
    jwt = send_major_login(session, at, oi, region_code, device_info)
    if not jwt: return {"success": False, "error": "Major Login Failed (check logs — likely DataDome/region mismatch)"}

    # 5. Gateway
    gw_ok = get_login_data(session, jwt, oi, region_code, device_info)

    # 6. Homer
    homer_ok = equip_homer(session, jwt, region_code, device_info)

    # Decode account_id from JWT payload
    aid = None
    try:
        import base64
        pl = jwt.split('.')[1] + '=' * (-len(jwt.split('.')[1]) % 4)
        jd = json.loads(base64.urlsafe_b64decode(pl))
        aid = jd.get("account_id") or jd.get("uid") or "N/A"
    except: aid = "N/A"

    return {
        "success": True,
        "message": f"Activated (gateway={'OK' if gw_ok else 'FAIL'}, homer={'OK' if homer_ok else 'FAIL'})",
        "uid": uid, "password": password, "account_id": aid,
        "region": region_code, "device": device_info["model"], "jwt": jwt
    }

# ── API ──
class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        qs = parse_qs(urlparse(self.path).query)
        if path == "/api/activate":
            uid = qs.get("uid", [""])[0]
            pwd = qs.get("password", [""])[0]
            region = qs.get("region", ["IND"])[0].upper()
            if not uid or not pwd: return self._json(400, {"error": "Missing uid/password"})
            result = activate_account(uid, pwd, region)
            return self._json(200 if result["success"] else 400, result)
        return self._json(404, {"error": "Not found"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8081))
    print(f"💀 KAMOD Activator (IND Fixed) Running on Port {port} 💀")
    print(f"🔗 GET /api/activate?uid=XXX&password=YYY&region=IND")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()