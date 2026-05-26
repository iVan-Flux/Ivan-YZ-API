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

# Load configurations and secrets from environment variables
IVANZ_BASE = os.getenv("IVANZ_BASE")
EVENTS_PATH = os.getenv("EVENTS_PATH", "events.txt")
CATEGORIES_PATH = os.getenv("CATEGORIES_PATH", "categories.txt")
SPORTS_PATH = os.getenv("SPORTS_PATH", "sports.txt")
IVANZ_ALPHA = os.getenv("IVANZ_ALPHA")
IVANZ_MAPPED = os.getenv("IVANZ_MAPPED")

# Initialize decryption keys dynamically from secrets
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
        print(f"Error parsing DECRYPTION_KEYS: {e}")

def custom_substitute_ivanz(data):
    if not IVANZ_ALPHA or not IVANZ_MAPPED:
        return data
    result = []
    for char in data:
        idx = IVANZ_MAPPED.find(char)
        if idx != -1:
            result.append(IVANZ_ALPHA[idx])
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
    print(f"Processing {total} embedded links...")

    def process_item(item):
        url = IVANZ_BASE + item['path']
        raw_text = fetch_url(url)
        if raw_text:
            decrypted = decrypt_ivanz_data(raw_text, embed=False)
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

def decrypt_ivanz_data(raw_data, embed=True):
    if not raw_data or not isinstance(raw_data, str):
        return None
        
    decrypted_str = None
    try:
        substituted = custom_substitute_ivanz(raw_data)
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

def parse_datetime_to_object(date_str, time_str):
    if not time_str:
        return None
        
    if not date_str:
        date_str = datetime.utcnow().strftime("%d/%m/%Y")
        
    date_str = date_str.replace('-', '/')
    
    time_parts = time_str.strip().split(':')
    if len(time_parts) == 2:
        time_str_cleaned = f"{time_parts[0]}:{time_parts[1]}:00"
    elif len(time_parts) == 3:
        time_str_cleaned = f"{time_parts[0]}:{time_parts[1]}:{time_parts[2]}"
    else:
        time_str_cleaned = "00:00:00"

    for fmt in ("%d/%m/%Y", "%Y/%m/%d"):
        try:
            combined_str = f"{date_str} {time_str_cleaned}"
            return datetime.strptime(combined_str, f"{fmt} %H:%M:%S")
        except ValueError:
            pass
    return None

def estimate_duration_by_category(category, event_name):
    cat_lower = str(category).lower()
    name_lower = str(event_name).lower()

    if "football" in cat_lower or "football" in name_lower or "soccer" in cat_lower:
        return 150  # 2.5 hours

    if "cricket" in cat_lower or "cricket" in name_lower:
        if "t20" in name_lower or "t-20" in name_lower or "ipl" in name_lower or "t20" in cat_lower:
            return 240  # 4 hours
        if "odi" in name_lower or "odi" in cat_lower or "50 over" in name_lower:
            return 480  # 8 hours
        if "test" in name_lower or "test" in cat_lower:
            return 480  # 8 hours
        return 240  # fallback standard cricket match

    if "tennis" in cat_lower or "tennis" in name_lower:
        return 180  # 3 hours

    if "kabaddi" in cat_lower or "kabadi" in cat_lower or "kabaddi" in name_lower:
        return 60   # 1 hour

    return 120  # default fallback duration is 2 hours

def replace_brand_names(obj):
    """
    Recursively replaces branding words like 'PLAYZ TV' or 'PLAYZ' with 'IVANZ TV' or 'IVANZ'
    """
    if isinstance(obj, str):
        temp = re.sub(re.escape("PLAYZ TV"), "IVANZ TV", obj, flags=re.IGNORECASE)
        temp = re.sub(re.escape("PLAYZ"), "IVANZ", temp, flags=re.IGNORECASE)
        return temp
    elif isinstance(obj, dict):
        return {replace_brand_names(k): replace_brand_names(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [replace_brand_names(x) for x in obj]
    return obj

def format_events_data(events_array, current_ist_time, event_cats={}, shift_minutes=240):
    if not isinstance(events_array, list):
        return events_array, 0, 0, 0

    formatted = []
    live_count = 0
    upcoming_count = 0
    finished_count = 0

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
        
        category = event_obj.get('category', '')
        event_name = event_obj.get('eventName', event_obj.get('match_name', event_obj.get('title', 'Live Event')))

        # Parse start and end datetimes
        start_dt = parse_datetime_to_object(raw_date, raw_time)
        end_dt = parse_datetime_to_object(raw_end_date, raw_end_time)

        # Apply timezone adjustments
        if start_dt:
            start_dt = start_dt + timedelta(minutes=shift_minutes)
            
        if end_dt:
            end_dt = end_dt + timedelta(minutes=shift_minutes)
        elif start_dt:
            duration = estimate_duration_by_category(category, event_name)
            end_dt = start_dt + timedelta(minutes=duration)

        # Standardizing output formats
        start_time_output = start_dt.strftime("%d/%m/%Y %H:%M:%S") if start_dt else ""
        end_time_output = end_dt.strftime("%d/%m/%Y %H:%M:%S") if end_dt else ""

        # Dynamic Status Logic relative to Current IST Time
        status = "Upcoming"
        if start_dt and end_dt:
            if start_dt <= current_ist_time <= end_dt:
                status = "Live"
                live_count += 1
            elif current_ist_time > end_dt:
                status = "Finished"
                finished_count += 1
            else:
                status = "Upcoming"
                upcoming_count += 1
        else:
            upcoming_count += 1

        final_links = event_obj.get('links', event_obj.get('Multiple URL', []))
        if not isinstance(final_links, list):
            final_links = []

        formatted.append({
            "match_id": str(event_obj.get('id', event_obj.get('match_id', ''))),
            "category": category,
            "eventName": event_name,
            "event_name": event_name,
            "eventLogo": event_obj.get('eventLogo', event_obj.get('logo', event_obj.get('image', event_cats.get(category, '')))),
            "teamAName": event_obj.get('teamAName', event_obj.get('team1Name', 'Team A')),
            "teamBName": event_obj.get('teamBName', event_obj.get('team2Name', 'Team B')),
            "teamAFlag": event_obj.get('teamAFlag', event_obj.get('team1Logo', '')),
            "teamBFlag": event_obj.get('teamBFlag', event_obj.get('team2Logo', '')),
            "start Time": start_time_output,
            "end Time": end_time_output,
            "visible": event_obj.get('visible', True),
            "isHot": event_obj.get('isHot', False),
            "Status": status,
            "links": final_links,
            "start_dt_obj": start_dt  # Kept temporarily for sorting
        })

    # Sort logic: Live first, then Upcoming (sorted by start time), then Finished
    live_events = [e for e in formatted if e["Status"] == "Live"]
    upcoming_events = [e for e in formatted if e["Status"] == "Upcoming"]
    finished_events = [e for e in formatted if e["Status"] == "Finished"]

    # Sort upcoming events by start datetime safely
    upcoming_events.sort(key=lambda x: x["start_dt_obj"] if x["start_dt_obj"] else datetime.max)
    live_events.sort(key=lambda x: x["start_dt_obj"] if x["start_dt_obj"] else datetime.min)
    finished_events.sort(key=lambda x: x["start_dt_obj"] if x["start_dt_obj"] else datetime.min, reverse=True)

    sorted_events = live_events + upcoming_events + finished_events

    # Clean sorting objects before final dumping
    for ev in sorted_events:
        if "start_dt_obj" in ev:
            del ev["start_dt_obj"]

    return sorted_events, live_count, upcoming_count, finished_count

def main():
    if not IVANZ_BASE:
        print("Error: Missing required config variable (IVANZ_BASE).")
        return

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Calculate real-time dynamic IST (UTC + 5:30) for workflow updates
    utc_now = datetime.utcnow()
    ist_now = utc_now + timedelta(hours=5, minutes=30)
    ist_formatted_string = ist_now.strftime("%I:%M:%S %p %d-%m-%Y")

    # 1. Processing Events payload
    print("Decrypting Events data...")
    events_url = IVANZ_BASE + EVENTS_PATH
    raw_events = fetch_url(events_url)
    formatted_events = []
    live_c, upcoming_c, finished_c = 0, 0, 0
    
    if raw_events:
        decrypted_events = decrypt_ivanz_data(raw_events, embed=True)
        event_cats = {}
        try:
            cats_url = IVANZ_BASE + "event_cats.txt"
            raw_cats = fetch_url(cats_url)
            if raw_cats:
                cats_decrypted = decrypt_ivanz_data(raw_cats, embed=False)
                if cats_decrypted and isinstance(cats_decrypted, dict):
                    event_cats = cats_decrypted
        except Exception:
            pass

        if isinstance(decrypted_events, list):
            formatted_events, live_c, upcoming_c, finished_c = format_events_data(
                decrypted_events, ist_now, event_cats, shift_minutes=240
            )
        else:
            formatted_events = decrypted_events
    else:
        print("Warning: Events stream could not be loaded.")

    # 2. Processing Categories payload
    print("Decrypting Categories data...")
    categories_url = IVANZ_BASE + CATEGORIES_PATH
    raw_categories = fetch_url(categories_url)
    decrypted_categories = []
    if raw_categories:
        decrypted_categories = decrypt_ivanz_data(raw_categories, embed=False) or []

    # 3. Processing Sports payload
    print("Decrypting Sports data...")
    sports_url = IVANZ_BASE + SPORTS_PATH
    raw_sports = fetch_url(sports_url)
    decrypted_sports = []
    if raw_sports:
        decrypted_sports = decrypt_ivanz_data(raw_sports, embed=True) or []

    # Apply recursive branding replacement (PLAYZ -> IVANZ)
    formatted_events = replace_brand_names(formatted_events)
    decrypted_categories = replace_brand_names(decrypted_categories)
    decrypted_sports = replace_brand_names(decrypted_sports)

    # 4. Constructing Structured Header Response exactly as requested
    events_final_payload = {
        " NAME ": "FluX-YZ Live event ( Auto updated)",
        "AUTHOR": "iVan_FluX",
        "CONTACT (OWNER)": "https://t.me/iVan_flux",
        "TELEGRAM CHANNEL": "https://t.me/api_hub_by_ivan",
        "Last update time": ist_formatted_string,
        " Live : {:02d} ".format(live_c): "",
        "Upcoming : {:02d}".format(upcoming_c): "",
        "Finish : {:02d} ".format(finished_c): "",
        "events": formatted_events
    }

    # 5. Saving raw, clean unencrypted outputs
    print("Saving plain JSON files to disk...")
    
    with open(os.path.join(script_dir, "live-events.json"), "w", encoding="utf-8") as f:
        json.dump(events_final_payload, f, indent=4, ensure_ascii=False)

    with open(os.path.join(script_dir, "categories.json"), "w", encoding="utf-8") as f:
        json.dump(decrypted_categories, f, indent=4, ensure_ascii=False)

    with open(os.path.join(script_dir, "sports.json"), "w", encoding="utf-8") as f:
        json.dump(decrypted_sports, f, indent=4, ensure_ascii=False)

    print("Success: System updated successfully.")

if __name__ == "__main__":
    main()
