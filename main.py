import os
import json
import requests

#PayloadsNoSQL/neo4j/detection.json
# URL RAW del JSON en GitHub
URL = "https://raw.githubusercontent.com/WiloG2/PayloadsNoSQL/9d1a3f9fb02d4acbb605d0f48eb1182e4d16821a/neo4j/detection.json"

# Directorio de caché local
CACHE_DIR = ".cache/payloads"
CACHE_FILE = os.path.join(CACHE_DIR, "payloads.json")
ETAG_FILE = os.path.join(CACHE_DIR, "etag.txt")

def download_if_updated():
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)

    headers = {}
    if os.path.exists(ETAG_FILE):
        with open(ETAG_FILE, "r") as f:
            etag = f.read().strip()
            headers["If-None-Match"] = etag

    response = requests.get(URL, headers=headers)

    if response.status_code == 304:
        print("Payloads en cache actualizados.")
        return

    if response.status_code == 200:
        print("Nueva version detectada. Actualizando cache...")

        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(response.text)

        etag = response.headers.get("ETag")
        if etag:
            with open(ETAG_FILE, "w") as f:
                f.write(etag)

        print("Cache actualizado.")
    else:
        print("Error inesperado:", response.status_code)

def load_payloads():
    """Carga los payloads desde el archivo JSON."""
    with open(CACHE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def get_payload_by_id(payloads, payload_id):
    """Retorna el payload basado en su ID."""
    for p in payloads:
        if p["id"] == payload_id:
            return p
    return None


# --- MAIN ---
download_if_updated()
payloads = load_payloads()

# Cambia este ID para probar
payload_id = "cypher-id-001"

payload_data = get_payload_by_id(payloads, payload_id)

if payload_data:
    print("Payload:", payload_data["payload"])
else:
    print(f"No se encontró el payload con id: {payload_id}")
