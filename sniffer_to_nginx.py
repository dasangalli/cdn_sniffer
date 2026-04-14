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

IP2LOCATION_API_KEY = "CCC14E23F2330AA73D3A535FB07D2DC2"
CDN_COUNTRY_PRIORITY = {"IT": 0, "GB": 1, "NL": 2, "DE": 3, "FR": 4, "US": 10}

def escape_nginx(s):
    """Sostituisce il simbolo $ con ${dlr} per evitare errori di variabili in Nginx."""
    if not s: return ""
    return str(s).replace('$', '${dlr}')

def get_performance_score(hostname: str) -> dict:
    host = hostname.split(":")[0]
    try:
        res = subprocess.run(["mtr", "-rw", "-c", "5", host], capture_output=True, text=True, timeout=15)
        lines = res.stdout.strip().split('\n')
        if not lines: return {"score": 0, "loss": 100, "avg": 999, "stdev": 999}
        parts = re.split(r'\s+', lines[-1])
        loss, avg, stdev = float(parts[2].replace('%','')), float(parts[5]), float(parts[9])
        score = round(max(0, 100 - (loss * 15) - (avg / 10) - (stdev * 5)), 2)
        return {"score": score, "loss": loss, "avg": avg, "stdev": stdev}
    except:
        return {"score": 0, "loss": 100, "avg": 999, "stdev": 999}

STREAM_CONF_TEMPLATE = """# =============================================================================
#  {conf_filename} - AUTO-GENERATO
# =============================================================================

location /live/{stream_id}/playlist.m3u8 {{
    sub_filter_once off;
    sub_filter_types application/vnd.apple.mpegurl application/x-mpegurl text/plain;
{cdn_sub_filters}
    sub_filter "{segment_prefix}-" "/live/{stream_id}/segment/{segment_prefix}-";

    proxy_set_header Referer          "{referer}";
    proxy_set_header Origin           "{origin}";
    proxy_set_header User-Agent       "{user_agent}";
    {cookie_line}

    proxy_set_header Host             "{primary_host_only}";
    proxy_pass        https://live_cdn_{stream_id}{playlist_path_escaped};
    proxy_ssl_server_name on;

    proxy_cache              playlist_cache;
    proxy_cache_valid        200 3s;
    proxy_cache_use_stale    error timeout updating;

    add_header X-Cache-Status $upstream_cache_status always;
    add_header X-Stream-ID    "{stream_id}" always;
    add_header Access-Control-Allow-Origin * always;
}}

location /live/{stream_id}/segment/ {{
    rewrite ^/live/{stream_id}/segment/(.*)$ /{cdn_path_prefix}$1 break;
    proxy_set_header Referer          "{referer}";
    {cookie_line}
    proxy_set_header Host             "{primary_host_only}";
    proxy_pass        https://live_cdn_{stream_id};
    proxy_ssl_server_name on;
    proxy_cache              segment_cache;
    proxy_cache_valid        200 10m;
    add_header X-Cache-Status $upstream_cache_status always;
}}
"""

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url")
    parser.add_argument("--stream-id", default="1")
    parser.add_argument("--sniff-only", action="store_true")
    parser.add_argument("--merge-dir")
    args = parser.parse_args()

    if args.sniff_only:
        res = sniff_once(args.url)
        if res:
            data = res[0]
            parsed = urlparse(data["url"])
            host = f"{parsed.hostname}:{parsed.port}" if parsed.port and parsed.port != 443 else parsed.hostname
            ip_res = requests.get(f"https://cloudflare-dns.com/dns-query?name={parsed.hostname}&type=A", headers={"Accept": "application/dns-json"}).json()
            ip = ip_res["Answer"][0]["data"] if "Answer" in ip_res else None
            geo = requests.get(f"https://api.ip2location.io/?key={IP2LOCATION_API_KEY}&ip={ip}").json() if ip else {}
            cdn_data = {"cdn_host": host, "cdn_country_code": geo.get("country_code", "XX"), "perf": get_performance_score(host)}
            with open(f"cdn_{args.stream_id}.json", "w") as f: json.dump({"cdn": cdn_data, "m3u8": data}, f)

    elif args.merge_dir:
        cdn_list = []
        first_m = None
        for f in glob.glob(os.path.join(args.merge_dir, "*.json")):
            with open(f) as j:
                d = json.load(j)
                cdn_list.append(d["cdn"])
                if not first_m: first_m = d["m3u8"]
        
        cdn_list = sorted(cdn_list, key=lambda x: (-x["perf"]["score"], CDN_COUNTRY_PRIORITY.get(x["cdn_country_code"], 5)))
        
        # Generazione Upstream
        u_lines = ""
        for i, cdn in enumerate(cdn_list):
            u_lines += f"    server {cdn['cdn_host']} {'backup ' if i > 0 else ''}max_fails=2 fail_timeout=30s;\n"
        
        with open(f"upstream_{args.stream_id}.conf", "w") as f:
            f.write(f"upstream live_cdn_{args.stream_id} {{\n{u_lines}    keepalive 32;\n}}\n")
        
        # Generazione Stream Config
        parsed = urlparse(first_m["url"])
        sub_filters = ""
        hls_folder = "/" + parsed.path.strip("/").split("/")[0] + "/"
        for cdn in cdn_list:
            sub_filters += f'    sub_filter "https://{cdn["cdn_host"]}{hls_folder}" "/live/{args.stream_id}/segment/";\n'

        common = {
            "stream_id": args.stream_id,
            "conf_filename": f"stream_{args.stream_id}.conf",
            "cdn_sub_filters": sub_filters,
            "segment_prefix": os.path.basename(parsed.path).split("-")[0],
            "referer": escape_nginx(first_m.get("referer", "")),
            "origin": escape_nginx(first_m.get("origin", "")),
            "user_agent": escape_nginx(first_m.get("user_agent", "")),
            "cookie_line": f'proxy_set_header Cookie "{escape_nginx(first_m["cookie"])}";' if first_m.get("cookie") else "",
            "playlist_path_escaped": escape_nginx(parsed.path + ("?" + parsed.query if parsed.query else "")),
            "cdn_path_prefix": parsed.path.strip("/").split("/")[0] + "/",
            "primary_host_only": cdn_list[0]['cdn_host'].split(":")[0]
        }
        with open(f"stream_{args.stream_id}.conf", "w") as f: f.write(STREAM_CONF_TEMPLATE.format(**common))
        
        # Database JSON per la sentinella
        with open(f"cdn_result_{args.stream_id}.json", "w") as f:
            json.dump({"all_cdns": cdn_list}, f)

if __name__ == "__main__": main()
