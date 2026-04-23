#!/usr/bin/env python3
import argparse, glob, json, os, re, subprocess, sys, time
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

try:
    from sniffer import sniff_once
except ImportError:
    print("[ERROR] sniffer.py non trovato.")
    sys.exit(1)

# Configurazione API per GeoIP
IP2LOCATION_API_KEY = "CCC14E23F2330AA73D3A535FB07D2DC2"
CDN_COUNTRY_PRIORITY = {"IT": 0, "GB": 1, "NL": 2, "DE": 3, "FR": 4, "US": 10}

def clean_for_nginx(s):
    """
    Versione ultra-sicura: rimuove i doppi apici e protegge il simbolo $.
    """
    if not s: return ""
    # 1. Convertiamo in stringa e RIMUOVIAMO i doppi apici (causa del 90% degli errori)
    s = str(s).replace('"', '') 
    
    # 2. Sostituiamo il dollaro con la variabile Nginx ${dlr}
    return s.replace('$', '${dlr}')

def _flag(code):
    if not code or len(code) != 2: return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())

def get_performance_score(hostname: str) -> dict:
    """MTR eseguito dal Runner (Solo indicativo per l'ordine iniziale)"""
    host = hostname.split(":")[0]
    try:
        res = subprocess.run(["mtr", "-rw", "-c", "5", host], capture_output=True, text=True, timeout=15)
        lines = res.stdout.strip().split('\n')
        if not lines: return {"score": 0, "loss": 100, "avg": 999, "stdev": 999}
        parts = [p for p in re.split(r'\s+', lines[-1].strip()) if p]
        loss  = float(parts[-7].replace('%',''))
        avg   = float(parts[-4])
        stdev = float(parts[-1])
        score = round(max(0, 100 - (loss * 15) - (avg / 10) - (stdev * 5)), 2)
        return {"score": score, "loss": loss, "avg": avg, "stdev": stdev}
    except:
        return {"score": 0, "loss": 100, "avg": 999, "stdev": 999}

# Template corretto: rimosso l'header Host statico, aggiunto $proxy_host
STREAM_CONF_TEMPLATE = """# =============================================================================
#  {conf_filename}
#  AUTO-GENERATO - Ottimizzato per failover dinamico
#  Generato il:    {generated_at}
#  Sorgente:       {source_url}
#  Playlist URL:   {playlist_url}
#  Scadenza token: {token_expires}
#  CDN primario:   {cdn_primary_info}
# =============================================================================

# ------------------------------------------------------------------
# PLAYLIST  /live/{stream_id}/playlist.m3u8
# ------------------------------------------------------------------
location /live/{stream_id}/playlist.m3u8 {{

    sub_filter_once off;
    sub_filter_types application/vnd.apple.mpegurl application/x-mpegurl text/plain;
    
{cdn_sub_filters}
    sub_filter "{segment_prefix}-" "/live/{stream_id}/segment/{segment_prefix}-";

    proxy_set_header Referer          "{referer}";
    proxy_set_header Origin           "{origin}";
    proxy_set_header User-Agent       "{user_agent}";
    proxy_set_header Accept           "*/*";
    proxy_set_header Accept-Language  "en-US,en;q=0.9";
    {cookie_line}

    # FIX: Usiamo $proxy_host per adattarsi dinamicamente al server dell'upstream
    proxy_set_header Host             $proxy_host;

    proxy_pass        https://live_cdn_{stream_id}{playlist_path_full};
    proxy_ssl_server_name on;

    proxy_cache              playlist_cache;
    proxy_cache_valid        200 3s;
    proxy_cache_lock         on;
    proxy_cache_use_stale    error timeout updating;
    proxy_cache_background_update on;

    add_header Cache-Control  "no-cache, no-store, must-revalidate" always;
    add_header X-Cache-Status $upstream_cache_status always;
    add_header X-Stream-ID    "{stream_id}" always;
    add_header Access-Control-Allow-Origin * always;
}}

# ------------------------------------------------------------------
# SEGMENTI  /live/{stream_id}/segment/
# ------------------------------------------------------------------
location /live/{stream_id}/segment/ {{
    rewrite ^/live/{stream_id}/segment/(.*)$ /hls/$1 break;

    proxy_set_header Referer          "{referer}";
    proxy_set_header Origin           "{origin}";
    proxy_set_header User-Agent       "{user_agent}";
    {cookie_line}
    
    proxy_set_header Host             $proxy_host;

    # Timeouts per evitare attese infinite su CDN lenti
    proxy_connect_timeout             3s;
    proxy_read_timeout                4s;
    proxy_send_timeout                4s;

    proxy_pass        https://live_cdn_{stream_id};
    proxy_ssl_server_name on;

    proxy_cache              segment_cache;
    proxy_cache_valid        200 10m;
    
    # Ottimizzazione Lock: evita il "dogpile effect"
    proxy_cache_lock         on;
    proxy_cache_lock_timeout 10s;
    proxy_cache_lock_age     5s;
    
    proxy_cache_revalidate   on;

    proxy_cache_use_stale    error timeout updating http_500 http_502 http_503 http_504;
    proxy_cache_background_update off;
    
    proxy_next_upstream error timeout invalid_header http_500 http_502 http_504;
    proxy_next_upstream_tries 2;
    proxy_next_upstream_timeout 5s;

    add_header Cache-Control  "max-age=600" always;
    add_header X-Cache-Status $upstream_cache_status always;
    add_header Access-Control-Allow-Origin * always;
}}
"""

def generate_configs(data, source_url, stream_id, cdn_list):
    playlist_url = data["url"].split("&__")[0]
    parsed = urlparse(playlist_url)
    
    # 1. Generazione Upstream
    u_lines = []
    for i, cdn in enumerate(cdn_list):
        backup = "backup " if i > 0 else ""
        u_lines.append(f"    server {cdn['cdn_host']} {backup}max_fails=1 fail_timeout=10s; # Score Runner: {cdn['perf']['score']}")
    
    upstream_content = f"upstream live_cdn_{stream_id} {{\n" + "\n".join(u_lines) + "\n    keepalive 32;\n}\n"

    # 2. Generazione Sub-filters
    sf_lines = []
    for cdn in cdn_list:
        host = cdn['cdn_host']
        sf_lines.append(f'    sub_filter "https://{host}/hls/" "/live/{stream_id}/segment/";')
        sf_lines.append(f'    sub_filter "https://{host}/storage/enc.key" "/live/{stream_id}/enc.key";')
    
    # 3. Preparazione Dati per il Template
    primary = cdn_list[0]
    token_exp = "N/D"
    for pat in [r"[&?]expires=(\d+)", r"[&?]e=(\d+)"]:
        m = re.search(pat, playlist_url)
        if m: 
            token_exp = datetime.fromtimestamp(int(m.group(1)), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    common = {
        "stream_id": stream_id,
        "conf_filename": f"stream_{stream_id}.conf",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_url": clean_for_nginx(source_url),
        "playlist_url": clean_for_nginx(playlist_url),
        "token_expires": token_exp,
        "cdn_primary_info": f"{_flag(primary.get('cdn_country_code'))} {primary['cdn_host']} ({primary.get('cdn_city', 'N/D')})",
        "cdn_sub_filters": "\n".join(sf_lines),
        "segment_prefix": os.path.basename(parsed.path).split(".")[0].split("-")[0],
        "referer": clean_for_nginx(data.get("referer", "")),
        "origin": clean_for_nginx(data.get("origin", "")),
        "user_agent": clean_for_nginx(data.get("user_agent", "")),
        "cookie_line": f'proxy_set_header Cookie "{clean_for_nginx(data["cookie"])}";' if data.get("cookie") else "# no cookie",
        "playlist_path_full": clean_for_nginx(parsed.path + ("?" + parsed.query if parsed.query else ""))
    }

    return upstream_content, STREAM_CONF_TEMPLATE.format(**common)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url")
    parser.add_argument("--stream-id", default="1")
    parser.add_argument("--sniff-only", action="store_true")
    parser.add_argument("--merge-dir")
    parser.add_argument("--sniff-timeout", type=int, default=15)
    parser.add_argument("--output", default="cdn_result.json")
    args = parser.parse_args()

    if args.sniff_only:
        res = sniff_once(args.url, timeout=args.sniff_timeout)
        if res:
            data = res[0]
            parsed = urlparse(data["url"].split("&__")[0])
            host = f"{parsed.hostname}:{parsed.port}" if parsed.port and parsed.port != 443 else parsed.hostname
            
            # DNS e GeoIP
            try:
                ip_res = requests.get(f"https://cloudflare-dns.com/dns-query?name={parsed.hostname}&type=A", headers={"Accept": "application/dns-json"}).json()
                ip = ip_res["Answer"][0]["data"] if "Answer" in ip_res else None
                geo = requests.get(f"https://api.ip2location.io/?key={IP2LOCATION_API_KEY}&ip={ip}").json() if ip else {}
            except:
                geo = {}

            cdn_data = {
                "cdn_host": host, 
                "cdn_country_code": geo.get("country_code", "XX"), 
                "cdn_city": geo.get("city_name", "N/D"), 
                "perf": get_performance_score(host)
            }
            
            with open(args.output, "w") as f:
                json.dump({"cdn": cdn_data, "m3u8": data}, f)

    elif args.merge_dir:
        cdn_list = []
        first_m = None
        for f_path in glob.glob(os.path.join(args.merge_dir, "*.json")):
            with open(f_path) as j:
                d = json.load(j)
                cdn_list.append(d["cdn"])
                if not first_m: first_m = d["m3u8"]
        
        if not cdn_list: return
        
        # Ordiniamo in base alla priorità geografica e allo score del Runner
        cdn_list = sorted(cdn_list, key=lambda x: (-x["perf"]["score"], CDN_COUNTRY_PRIORITY.get(x["cdn_country_code"], 5)))
        u, s = generate_configs(first_m, args.url, args.stream_id, cdn_list)
        
        with open(f"upstream_{args.stream_id}.conf", "w") as f: f.write(u)
        with open(f"stream_{args.stream_id}.conf", "w") as f: f.write(s)

if __name__ == "__main__":
    main()
