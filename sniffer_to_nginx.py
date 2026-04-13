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

# Priorità Geografica (Tie-breaker)
CDN_COUNTRY_PRIORITY = {"IT": 0, "GB": 1, "NL": 2, "DE": 3, "FR": 4, "US": 10}

# --- NETWORK & PERFORMANCE ENGINE ---

def get_performance_score(hostname: str) -> dict:
    """Esegue MTR e calcola lo Score Qualità: 100 - (Loss*15) - (Avg/10) - (StDev*5)"""
    host = hostname.split(":")[0]
    print(f"  [Bench] Testando performance verso {host}...", end=" ", flush=True)
    try:
        res = subprocess.run(["mtr", "-rw", "-c", "5", host], capture_output=True, text=True, timeout=20)
        lines = res.stdout.strip().split('\n')
        if not lines: return {"score": 0, "loss": 100, "avg": 999, "stdev": 999}
        parts = re.split(r'\s+', lines[-1])
        loss, avg, stdev = float(parts[2].replace('%','')), float(parts[5]), float(parts[9])
        score = round(max(0, 100 - (loss * 15) - (avg / 10) - (stdev * 5)), 2)
        print(f"DONE (Score: {score})")
        return {"score": score, "loss": loss, "avg": avg, "stdev": stdev}
    except:
        print("FALLITO")
        return {"score": 0, "loss": 100, "avg": 999, "stdev": 999}

def resolve_and_geolocate(hostname: str, api_key: str) -> dict:
    host = hostname.split(":")[0]
    try:
        dns_res = requests.get(f"https://cloudflare-dns.com/dns-query?name={host}&type=A", headers={"Accept": "application/dns-json"}).json()
        ip = dns_res["Answer"][0]["data"] if "Answer" in dns_res else None
        if ip:
            geo = requests.get(f"https://api.ip2location.io/?key={api_key}&ip={ip}").json()
            return {"cdn_host": hostname, "cdn_ip": ip, "cdn_country_code": geo.get("country_code", "XX"), "cdn_city": geo.get("city_name", "N/D")}
    except: pass
    return {"cdn_host": hostname, "cdn_ip": None, "cdn_country_code": "XX", "cdn_city": "N/D"}

# --- CONFIG GENERATOR ---

def generate_configs(data, source_url, stream_id, cdn_list):
    playlist_url = data["url"].split("&__")[0]
    parsed = urlparse(playlist_url)
    
    # Upstream with Failover & Scores
    u_lines = ""
    for i, cdn in enumerate(cdn_list):
        host = cdn["cdn_host"]
        p = cdn["perf"]
        backup = "backup " if i > 0 else ""
        u_lines += f"    server {host} {backup}max_fails=2 fail_timeout=30s; # Score: {p['score']} ({cdn['cdn_country_code']})\n"
    
    upstream_conf = f"upstream live_cdn_{stream_id} {{\n{u_lines}    keepalive 32;\n}}\n"

    # Stream locations
    sub_filters = ""
    seen_bases = set()
    for cdn in cdn_list:
        base = f"https://{cdn['cdn_host']}{os.path.dirname(parsed.path)}/"
        if base not in seen_bases:
            sub_filters += f'    sub_filter "{base}" "/live/{stream_id}/segment/";\n'
            seen_bases.add(base)

    stream_conf = f"""
# Stream ID: {stream_id} | Primario: {cdn_list[0]['cdn_host']} | Score: {cdn_list[0]['perf']['score']}
location = /live/{stream_id}/playlist.m3u8 {{
    sub_filter_once off;
    sub_filter_types application/vnd.apple.mpegurl application/x-mpegurl text/plain;
{sub_filters}
    sub_filter "{os.path.splitext(os.path.basename(parsed.path))[0]}-" "/live/{stream_id}/segment/{os.path.splitext(os.path.basename(parsed.path))[0]}-";
    proxy_set_header Referer "{data.get('referer', '')}";
    proxy_set_header User-Agent "{data.get('user_agent', '')}";
    {f'proxy_set_header Cookie "{data["cookie"]}";' if data.get("cookie") else ""}
    proxy_pass https://live_cdn_{stream_id}{parsed.path + ("?" + parsed.query if parsed.query else "")};
    proxy_ssl_server_name on;
}}
location /live/{stream_id}/segment/ {{
    rewrite ^/live/{stream_id}/segment/(.*)$ /{parsed.path.strip('/').split('/')[0]}/$1 break;
    proxy_pass https://live_cdn_{stream_id};
    proxy_ssl_server_name on;
    proxy_cache segment_cache;
    proxy_cache_valid 200 10m;
}}
"""
    return upstream_conf, stream_conf

# --- MODES ---

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url")
    parser.add_argument("--stream-id", default="1")
    parser.add_argument("--sniff-only", action="store_true")
    parser.add_argument("--merge-dir")
    parser.add_argument("--output", default="cdn_result.json")
    parser.add_argument("--sniff-timeout", type=int, default=15)
    parser.add_argument("--ip2loc-key", default=IP2LOCATION_API_KEY)
    args = parser.parse_args()

    if args.sniff_only:
        results = sniff_once(args.url, timeout=args.sniff_timeout)
        if results:
            data = results[0]
            parsed = urlparse(data["url"].split("&__")[0])
            host = f"{parsed.hostname}:{parsed.port}" if parsed.port and parsed.port != 443 else parsed.hostname
            geo = resolve_and_geolocate(host, args.ip2loc_key)
            geo["perf"] = get_performance_score(host)
            with open(args.output, "w") as f: json.dump({"cdn": geo, "m3u8": data}, f)
            
    elif args.merge_dir:
        cdn_list = []
        seen = set()
        first_m3u8 = None
        for fpath in glob.glob(os.path.join(args.merge_dir, "*.json")):
            with open(fpath) as f:
                d = json.load(f)
                if d["cdn"]["cdn_host"] not in seen:
                    seen.add(d["cdn"]["cdn_host"])
                    cdn_list.append(d["cdn"])
                    if not first_m3u8: first_m3u8 = d["m3u8"]
        
        # SORT BY PERFORMANCE SCORE
        cdn_list = sorted(cdn_list, key=lambda x: (-x["perf"]["score"], CDN_COUNTRY_PRIORITY.get(x["cdn_country_code"], 5)))
        
        u, s = generate_configs(first_m3u8, args.url, args.stream_id, cdn_list)
        with open(f"upstream_{args.stream_id}.conf", "w") as f: f.write(u)
        with open(f"stream_{args.stream_id}.conf", "w") as f: f.write(s)
        print(f"[OK] Generati conf per stream {args.stream_id}")

if __name__ == "__main__": main()
