#!/usr/bin/env python3
import argparse, glob, json, os, re, subprocess, sys, time
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

try:
    from sniffer import sniff_once, extract_domain
except ImportError:
    print("[ERROR] sniffer.py non trovato.")
    sys.exit(1)

IP2LOCATION_API_KEY = "CCC14E23F2330AA73D3A535FB07D2DC2"
CDN_COUNTRY_PRIORITY = {"IT": 0, "GB": 1, "NL": 2, "DE": 3, "FR": 4, "US": 10}

def _flag(code):
    if not code or len(code) != 2: return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())

def get_performance_score(hostname: str) -> dict:
    host = hostname.split(":")[0]
    try:
        res = subprocess.run(["mtr", "-rw", "-c", "5", host], capture_output=True, text=True, timeout=15)
        parts = re.split(r'\s+', res.stdout.strip().split('\n')[-1])
        loss, avg, stdev = float(parts[2].replace('%','')), float(parts[5]), float(parts[9])
        score = round(max(0, 100 - (loss * 15) - (avg / 10) - (stdev * 5)), 2)
        return {"score": score, "loss": loss, "avg": avg, "stdev": stdev}
    except:
        return {"score": 0, "loss": 100, "avg": 999, "stdev": 999}

# ---------------------------------------------------------------------------
# Template Professionale (Corrispondente al tuo stream_1.conf)
# ---------------------------------------------------------------------------

STREAM_CONF_TEMPLATE = """# =============================================================================
#  {conf_filename}
#  AUTO-GENERATO da sniffer_to_nginx.py - NON modificare manualmente
#
#  Stream ID:      {stream_id}
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
    
    # Sub-filters per tutti i CDN rilevati
{cdn_sub_filters}
    # Segmenti con path relativo
    sub_filter "{segment_prefix}-" "/live/{stream_id}/segment/{segment_prefix}-";

    proxy_set_header Referer          "{referer}";
    proxy_set_header Origin           "{origin}";
    proxy_set_header User-Agent       "{user_agent}";
    proxy_set_header Accept           "{accept}";
    proxy_set_header Accept-Language  "en-US,en;q=0.9";
    proxy_set_header Sec-Fetch-Dest   "empty";
    proxy_set_header Sec-Fetch-Mode   "cors";
    proxy_set_header Sec-Fetch-Site   "cross-site";
    {cookie_line}

    # Passiamo l'Host reale per evitare il 404 del CDN
    proxy_set_header Host             "{primary_host_only}";

    # Failover automatico tramite upstream
    proxy_pass        https://live_cdn_{stream_id}{playlist_path_full};
    proxy_ssl_server_name on;

    proxy_cache              playlist_cache;
    proxy_cache_valid        200 3s;
    proxy_cache_lock         on;
    proxy_cache_lock_timeout 2s;
    proxy_cache_use_stale    error timeout updating;
    proxy_cache_background_update on;

    add_header Cache-Control  "no-cache, no-store, must-revalidate" always;
    add_header X-Cache-Status $upstream_cache_status always;
    add_header X-Stream-ID    "{stream_id}" always;
    add_header Access-Control-Allow-Origin * always;
}}

# ------------------------------------------------------------------
# SEGMENTI  /live/{stream_id}/segment/...
# ------------------------------------------------------------------
location /live/{stream_id}/segment/ {{
    rewrite ^/live/{stream_id}/segment/(.*)$ /{cdn_path_prefix}$1 break;

    proxy_set_header Referer          "{referer}";
    proxy_set_header Origin           "{origin}";
    proxy_set_header User-Agent       "{user_agent}";
    {cookie_line}
    proxy_set_header Host             "{primary_host_only}";

    proxy_pass        https://live_cdn_{stream_id};
    proxy_ssl_server_name on;

    proxy_cache              segment_cache;
    proxy_cache_valid        200 10m;
    proxy_cache_lock         on;
    proxy_cache_lock_timeout 3s;
    proxy_cache_revalidate   on;
    proxy_cache_use_stale    error timeout updating;
    proxy_cache_background_update on;

    add_header Cache-Control  "max-age=600" always;
    add_header X-Cache-Status $upstream_cache_status always;
    add_header Access-Control-Allow-Origin * always;
}}
"""

def generate_configs(data, source_url, stream_id, cdn_list):
    playlist_url = data["url"].split("&__")[0]
    parsed = urlparse(playlist_url)
    
    # Upstream
    u_lines = ""
    for i, cdn in enumerate(cdn_list):
        backup = "backup " if i > 0 else ""
        u_lines += f"    server {cdn['cdn_host']} {backup}max_fails=2 fail_timeout=30s;\n"
    upstream_conf = f"upstream live_cdn_{stream_id} {{\n{u_lines}    keepalive 32;\n}}\n"

    # Sub-filters (Supporto Multi-CDN + enc.key)
    sub_filters = ""
    hls_folder = "/" + parsed.path.strip("/").split("/")[0] + "/"
    for cdn in cdn_list:
        host = cdn['cdn_host']
        sub_filters += f'    sub_filter "https://{host}{hls_folder}" "/live/{stream_id}/segment/";\n'
        sub_filters += f'    sub_filter "https://{host}/storage/enc.key" "/live/{stream_id}/enc.key";\n'

    primary = cdn_list[0]
    token_exp = None
    for pat in [r"[&?]expires=(\d+)", r"[&?]e=(\d+)"]:
        m = re.search(pat, playlist_url)
        if m: token_exp = datetime.fromtimestamp(int(m.group(1)), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    common = {
        "stream_id": stream_id,
        "conf_filename": f"stream_{stream_id}.conf",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_url": source_url,
        "playlist_url": playlist_url,
        "token_expires": token_exp or "N/D",
        "cdn_primary_info": f"{_flag(primary['cdn_country_code'])} {primary['cdn_host']} ({primary['cdn_city']}, {primary['cdn_country_code']})",
        "cdn_sub_filters": sub_filters,
        "segment_prefix": os.path.splitext(os.path.basename(parsed.path))[0].split("-")[0],
        "referer": data.get("referer", ""),
        "origin": data.get("origin", ""),
        "user_agent": data.get("user_agent", ""),
        "accept": data.get("accept", "*/*"),
        "cookie_line": f'proxy_set_header Cookie "{data["cookie"]}";' if data.get("cookie") else "# no cookie",
        "playlist_path_full": parsed.path + ("?" + parsed.query if parsed.query else ""),
        "cdn_path_prefix": parsed.path.strip("/").split("/")[0] + "/",
        "primary_host_only": primary['cdn_host'].split(":")[0] # Rimuove la porta per l'header Host
    }

    return upstream_conf, STREAM_CONF_TEMPLATE.format(**common)

# ---------------------------------------------------------------------------
# Main Logic
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url")
    parser.add_argument("--stream-id", default="1")
    parser.add_argument("--sniff-only", action="store_true")
    parser.add_argument("--merge-dir")
    parser.add_argument("--output", default="cdn_result.json")
    parser.add_argument("--sniff-timeout", type=int, default=15)
    args = parser.parse_args()

    if args.sniff_only:
        res = sniff_once(args.url, timeout=args.sniff_timeout)
        if res:
            data = res[0]
            parsed = urlparse(data["url"].split("&__")[0])
            host = f"{parsed.hostname}:{parsed.port}" if parsed.port and parsed.port != 443 else parsed.hostname
            # Geo & Performance
            ip_res = requests.get(f"https://cloudflare-dns.com/dns-query?name={parsed.hostname}&type=A", headers={"Accept": "application/dns-json"}).json()
            ip = ip_res["Answer"][0]["data"] if "Answer" in ip_res else None
            geo = requests.get(f"https://api.ip2location.io/?key={IP2LOCATION_API_KEY}&ip={ip}").json() if ip else {}
            cdn_data = {"cdn_host": host, "cdn_country_code": geo.get("country_code", "XX"), "cdn_city": geo.get("city_name", "N/D"), "cdn_country_name": geo.get("country_name", "N/D"), "perf": get_performance_score(host)}
            with open(args.output, "w") as f: json.dump({"cdn": cdn_data, "m3u8": data}, f)

    elif args.merge_dir:
        cdn_list = []
        first_m = None
        for f in glob.glob(os.path.join(args.merge_dir, "*.json")):
            with open(f) as j:
                d = json.load(j)
                cdn_list.append(d["cdn"])
                if not first_m: first_m = d["m3u8"]
        cdn_list = sorted(cdn_list, key=lambda x: (-x["perf"]["score"], CDN_COUNTRY_PRIORITY.get(x["cdn_country_code"], 5)))
        u, s = generate_configs(first_m, args.url, args.stream_id, cdn_list)
        with open(f"upstream_{args.stream_id}.conf", "w") as f: f.write(u)
        with open(f"stream_{args.stream_id}.conf", "w") as f: f.write(s)

if __name__ == "__main__": main()
