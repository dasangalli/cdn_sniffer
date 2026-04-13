#!/usr/bin/env python3
import re, time, requests
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

def extract_domain(url: str) -> str:
    m = re.match(r"(https?://[^/]+)", url)
    return m.group(1) if m else url

def _is_m3u8(url, ct):
    return ".m3u8" in url.lower() or "mpegurl" in ct.lower()

def sniff_once(url: str, timeout: int = 10) -> list:
    found = []
    seen = set()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(user_agent=DEFAULT_USER_AGENT)
        page = context.new_page()
        def on_response(response):
            try:
                ct = response.headers.get("content-type", "")
                if _is_m3u8(response.url, ct) and response.url not in seen:
                    seen.add(response.url)
                    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in context.cookies()])
                    found.append({
                        "url": response.url,
                        "referer": response.request.headers.get("referer", ""),
                        "origin": response.request.headers.get("origin", extract_domain(url)),
                        "user_agent": DEFAULT_USER_AGENT,
                        "cookie": cookie_str,
                        "accept": response.request.headers.get("accept", "*/*"),
                    })
            except: pass
        page.on("response", on_response)
        try: page.goto(url, wait_until="domcontentloaded", timeout=30000)
        except: pass
        page.wait_for_timeout(timeout * 1000)
        browser.close()
    return found
