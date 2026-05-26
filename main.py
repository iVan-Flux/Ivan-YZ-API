import os
import json
import base64
import re
import urllib.request
import ssl
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# গিটহাব সিক্রেটস থেকে কনফিগারেশন এবং সিক্রেট ভ্যালুগুলো লোড করা হচ্ছে
PLAYZ_BASE = os.getenv("PLAYZ_BASE")
AES_SECRET = os.getenv("AES_SECRET")

# ডাইনামিক সোর্স ফাইল পাথ
EVENTS_PATH = os.getenv("EVENTS_PATH", "events.txt")
CATEGORIES_PATH = os.getenv("CATEGORIES_PATH", "categories.txt")
SPORTS_PATH = os.getenv("SPORTS_PATH", "sports.txt")

# ডাইনামিক ক্যারেক্টার ম্যাপ
PLAYZ_ALPHA = os.getenv("PLAYZ_ALPHA")
PLAYZ_MAPPED = os.getenv("PLAYZ_MAPPED")

# ডাইনামিক ডিক্রিপশন কী-লিস্ট লোড
KEYS = []
raw_keys_env = os.getenv("DECRYPTION_KEYS")
if raw_keys_env:
    try:
        parsed_keys = json.loads(raw_keys_env)
        for item in parsed_keys:
            KEYS.append({
                "key": item["key"].encode('utf-8'),
                "iv": item["iv"].encode('utf-8')
            })
    except Exception as e:
        print(f"Error parsing DECRYPTION_KEYS JSON: {e}")

def custom_substitute_playz(data):
    if not PLAYZ_ALPHA or not PLAYZ_MAPPED:
        return data
    result = []
    for char in data:
        idx = PLAYZ_MAPPED.find(char)
        if idx != -1:
            result.append(PLAYZ_ALPHA[idx])
        else:
            result.append(char)
    return "".join(result)

def decrypt_aes_cbc(data_bytes, key, iv):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data_bytes)
        return unpad(decrypted, AES.block_size).decode('utf-8')
    except Exception:
        return None

def unpack_json(data):
    if isinstance(data, list):
        for i in range(len(data)):
            data[i] = unpack_json(data[i])
    elif isinstance(data, dict):
        for k in list(data.keys()):
            v = data[k]
            if isinstance(v, str) and (v.startswith('{') or v.startswith('[')):
                try:
                    data[k] = unpack_json(json.loads(v))
                except json.JSONDecodeError:
                    pass
            else:
                data[k] = unpack_json(v)
    return data

def collect_embedded_links(data, lst=None):
    if lst is None:
        lst = []
    if isinstance(data, list):
        for i in range(len(data)):
            collect_embedded_links(data[i], lst)
    elif isinstance(data, dict):
        if 'link_names' in data:
            del data['link_names']
        for k, v in list(data.items()):
            if k in ('api', 'links', 'Multiple URL') and isinstance(v, str) and v.endswith('.txt'):
                lst.append({'parent': data, 'key': k, 'path': v})
            else:
                collect_embedded_links(v, lst)
    return lst

def fetch_url(url, retries=3):
    req = urllib.request.Request(url, headers={'User-Agent': 'Dalvik/2.1.0'})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
                return response.read().decode('utf-8').strip()
        except Exception as e:
            if attempt == retries - 1:
                print(f"Fetch failed for {url}: {e}")
                return None

def embed_links(data):
    lst = collect_embedded_links(data)
    if not lst:
        return data

    total = min(len(lst), 40)
    print(f"Found {len(lst)} embedded links. Processing {total}...")

    def process_item(item):
        url = PLAYZ_BASE + item['path']
        raw_text = fetch_url(url)
        if raw_text:
            decrypted = decrypt_playz_data(raw_text, embed=False)
            if decrypted:
                return item, decrypted
            else:
                return item, [{"name": "Error", "link": "Decryption failed"}]
        else:
            return item, [{"name": "Error", "link": "Fetch failed"}]

    processed = 0
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(process_item, item) for item in lst]
        for future in as_completed(futures):
            processed += 1
            item, result = future.result()
            item['parent'][item['key']] = result

    return data

def try_decrypt(data_str):
    try:
        clean1 = re.sub(r'[^A-Za-z0-9+/=]', '', data_str)
        while len(clean1) % 4 != 0:
            clean1 += '='
            
        binary1 = base64.b64decode(clean1)
        
        for k in KEYS:
            dec = decrypt_aes_cbc(binary1, k['key'], k['iv'])
            if dec:
                return dec
                
        try:
            intermediate = binary1.decode('utf-8', errors='replace').strip()
            clean2 = re.sub(r'[^A-Za-z0-9+/=]', '', intermediate)
            while len(clean2) % 4 != 0:
                clean2 += '='
            binary2 = base64.b64decode(clean2)
            for k in KEYS:
                dec = decrypt_aes_cbc(binary2, k['key'], k['iv'])
                if dec:
                    return dec
        except Exception:
            pass
    except Exception:
        pass
    return None

def decrypt_playz_data(raw_data, embed=True):
    if not raw_data or not isinstance(raw_data, str):
        return None
        
    decrypted_str = None
    try:
        substituted = custom_substitute_playz(raw_data)
        decrypted_str = try_decrypt(substituted)
        if not decrypted_str:
            decrypted_str = try_decrypt(raw_data)
    except Exception:
        pass
        
    if not decrypted_str:
        return None
        
    try:
        clean_decrypted = decrypted_str.replace('\0', '').strip()
        last_brace = max(clean_decrypted.rfind('}'), clean_decrypted.rfind(']'))
        if last_brace != -1:
            clean_decrypted = clean_decrypted[:last_brace+1]
            
        parsed = json.loads(clean_decrypted)
        unpacked = unpack_json(parsed)
        
        if embed:
            embed_links(unpacked)
            
        return unpacked
    except Exception as e:
        print(f"JSON Parse Error: {e}")
        return None

def adjust_datetime(date_str, time_str, shift_minutes):
    if not shift_minutes:
        return {"date": date_str, "time": time_str}
        
    d = None
    if time_str and 'T' in time_str:
        date_to_parse = time_str
        if 'Z' not in time_str and '+' not in time_str:
            date_to_parse += 'Z'
        try:
            date_to_parse = date_to_parse.replace('Z', '+0000')
            d = datetime.strptime(date_to_parse, "%Y-%m-%dT%H:%M:%S%z")
        except ValueError:
            pass
    elif date_str and time_str:
        parts = date_str.split('/') if '/' in date_str else date_str.split('-')
        if len(parts) == 3 and len(parts[0]) <= 2:
            try:
                d = datetime.strptime(f"{parts[2]}-{parts[1]}-{parts[0]}T{time_str}+0000", "%Y-%m-%dT%H:%M:%S%z")
            except ValueError:
                pass
        else:
            try:
                d = datetime.strptime(f"{date_str}T{time_str}+0000", "%Y-%m-%dT%H:%M:%S%z")
            except ValueError:
                pass
    elif time_str:
        parts = time_str.strip().split(':')
        h = int(parts[0])
        m = int(parts[1]) if len(parts) > 1 else 0
        s = int(parts[2]) if len(parts) > 2 else 0
        total_mins = h * 60 + m + shift_minutes
        total_mins = ((total_mins % 1440) + 1440) % 1440
        new_h = total_mins // 60
        new_m = total_mins % 60
        return {"date": date_str, "time": f"{new_h:02d}:{new_m:02d}:{s:02d}"}

    if d:
        d = d + timedelta(minutes=shift_minutes)
        return {"date": d.strftime("%d/%m/%Y"), "time": d.strftime("%H:%M:%S")}

    return {"date": date_str, "time": time_str}

def format_events_data(events_array, event_cats={}, shift_minutes=0):
    if not isinstance(events_array, list):
        return events_array

    formatted = []
    for item in events_array:
        if not item:
            continue
        event_obj = item.get('event', item) if isinstance(item, dict) else item
        if isinstance(event_obj, str):
            try:
                event_obj = json.loads(event_obj)
            except:
                pass
        if not isinstance(event_obj, dict):
            continue

        raw_time = event_obj.get('startTime', event_obj.get('matchTime', event_obj.get('time', '')))
        raw_end_time = event_obj.get('endTime', event_obj.get('matchEndTime', event_obj.get('end_time', '')))
        raw_date = event_obj.get('date', '')
        raw_end_date = event_obj.get('endDate', event_obj.get('date', ''))

        start_adj = adjust_datetime(raw_date, raw_time, shift_minutes)
        end_adj = adjust_datetime(raw_end_date, raw_end_time, shift_minutes)

        m_date_str = start_adj.get('date', '')
        m_time_str = start_adj.get('time', '')
        m_end_date_str = end_adj.get('date', '')
        m_end_time_str = end_adj.get('time', '')

        start_time_combined = f"{m_date_str} {m_time_str}".strip() if m_date_str and m_time_str else (m_time_str or "")

        final_links = event_obj.get('links', event_obj.get('Multiple URL', []))
        if not isinstance(final_links, list):
            final_links = []

        formatted.append({
            "match_id": str(event_obj.get('id', event_obj.get('match_id', ''))),
            "category": event_obj.get('category', ''),
            "eventName": event_obj.get('eventName', event_obj.get('match_name', event_obj.get('title', 'Live Event'))),
            "event_name": event_obj.get('eventName', event_obj.get('match_name', event_obj.get('title', 'Live Event'))),
            "eventLogo": event_obj.get('eventLogo', event_obj.get('logo', event_obj.get('image', event_cats.get(event_obj.get('category', ''), '')))),
            "teamAName": event_obj.get('teamAName', event_obj.get('team1Name', 'Team A')),
            "teamBName": event_obj.get('teamBName', event_obj.get('team2Name', 'Team B')),
            "teamAFlag": event_obj.get('teamAFlag', event_obj.get('team1Logo', '')),
            "teamBFlag": event_obj.get('teamBFlag', event_obj.get('team2Logo', '')),
            "startTime": start_time_combined,
            "time": m_time_str,
            "date": m_date_str,
            "endTime": m_end_time_str,
            "endDate": m_end_date_str,
            "visible": event_obj.get('visible', True),
            "isHot": event_obj.get('isHot', False),
            "links": final_links,
            "provider_name": "OMNIX PLAY",
            "priority": event_obj.get('priority', 0)
        })

    return formatted

def encrypt_data_eax(payload_bytes, secret_key):
    """
    Encrypts payloads securely to AES-EAX format.
    Packed structure: Base64( nonce [16 bytes] + tag [16 bytes] + ciphertext ) inside {"data": ...}
    """
    key_bytes = secret_key.encode('utf-8')[:32]
    nonce = os.urandom(16)  # Ensures explicit 16-byte secure random nonce
    cipher = AES.new(key_bytes, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(payload_bytes)
    
    combined_blob = nonce + tag + ciphertext
    encoded_data = base64.b64encode(combined_blob).decode('utf-8')
    return {"data": encoded_data}

def main():
    if not PLAYZ_BASE or not AES_SECRET:
        print("Error: Missing required configuration variables (PLAYZ_BASE or AES_SECRET).")
        return

    # ১. Events ডেটা প্রোসেসিং ও ডিক্রিপশন
    print("Decrypting Events data...")
    events_url = PLAYZ_BASE + EVENTS_PATH
    raw_events = fetch_url(events_url)
    formatted_events = []
    
    if raw_events:
        decrypted_events = decrypt_playz_data(raw_events, embed=True)
        event_cats = {}
        try:
            cats_url = PLAYZ_BASE + "event_cats.txt"
            raw_cats = fetch_url(cats_url)
            if raw_cats:
                cats_decrypted = decrypt_playz_data(raw_cats, embed=False)
                if cats_decrypted and isinstance(cats_decrypted, dict):
                    event_cats = cats_decrypted
        except Exception:
            pass

        if isinstance(decrypted_events, list):
            formatted_events = format_events_data(decrypted_events, event_cats, shift_minutes=240)
        else:
            formatted_events = decrypted_events
    else:
        print("Warning: Events stream could not be loaded.")

    # ২. Categories ডেটা প্রোসেসিং ও ডিক্রিপশন
    print("Decrypting Categories data...")
    categories_url = PLAYZ_BASE + CATEGORIES_PATH
    raw_categories = fetch_url(categories_url)
    decrypted_categories = []
    if raw_categories:
        decrypted_categories = decrypt_playz_data(raw_categories, embed=False) or []

    # ৩. Sports ডেটা প্রোসেসিং ও ডিক্রিপশন
    print("Decrypting Sports data...")
    sports_url = PLAYZ_BASE + SPORTS_PATH
    raw_sports = fetch_url(sports_url)
    decrypted_sports = []
    if raw_sports:
        decrypted_sports = decrypt_playz_data(raw_sports, embed=True) or []

    # ৪. AES-EAX ডাইনামিক এনক্রিপশন ও লোকাল সেভিং
    print("Saving payloads as EAX encrypted JSONs...")
    
    events_bytes = json.dumps(formatted_events, sort_keys=False, ensure_ascii=False).encode('utf-8')
    encrypted_events = encrypt_data_eax(events_bytes, AES_SECRET)
    with open("live-events.json", "w", encoding="utf-8") as f:
        json.dump(encrypted_events, f)

    categories_bytes = json.dumps(decrypted_categories, sort_keys=False, ensure_ascii=False).encode('utf-8')
    encrypted_categories = encrypt_data_eax(categories_bytes, AES_SECRET)
    with open("categories.json", "w", encoding="utf-8") as f:
        json.dump(encrypted_categories, f)

    sports_bytes = json.dumps(decrypted_sports, sort_keys=False, ensure_ascii=False).encode('utf-8')
    encrypted_sports = encrypt_data_eax(sports_bytes, AES_SECRET)
    with open("sports.json", "w", encoding="utf-8") as f:
        json.dump(encrypted_sports, f)

    print("Execution Finished.")

if __name__ == "__main__":
    main()
