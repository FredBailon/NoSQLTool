from config import *
from payloads.resolver import resolve_payload_url
from payloads.cache import download_if_updated
from payloads.loader import load_payloads
import os

engine = "mongo"
mode = "detection"

url = resolve_payload_url(GITHUB_RAW_BASE, engine, mode)

cache_file = f"{CACHE_DIR}/{engine}_{mode}.json"
etag_file = f"{cache_file}.etag"

updated = download_if_updated(url, cache_file, etag_file, FETCH_TIMEOUT)

if updated:
    print(f"Cache actualizado desde GitHub")
else:
    print(f"Cache sin cambios (ETag valido)")

payloads = load_payloads(cache_file)

print(f"Cargados {len(payloads)} payloads para {engine}/{mode}")
