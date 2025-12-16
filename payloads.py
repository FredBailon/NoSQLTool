import os
import json
import requests

# URL RAW del JSON en GitHub (ambiente controlado)
URL = "https://raw.githubusercontent.com/WiloG2/PayloadsNoSQL/9d1a3f9fb02d4acbb605d0f48eb1182e4d16821a/neo4j/detection.json"

# Directorio de caché local
CACHE_DIR = ".cache/payloads"
CACHE_FILE = os.path.join(CACHE_DIR, "payloads.json")
ETAG_FILE = os.path.join(CACHE_DIR, "etag.txt")


def download_if_updated():
    """Descarga el archivo de payloads si hay una versión nueva.

    Usa ETag para evitar descargas innecesarias.
    """
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)

    headers = {}
    if os.path.exists(ETAG_FILE):
        with open(ETAG_FILE, "r") as f:
            etag = f.read().strip()
            if etag:
                headers["If-None-Match"] = etag

    response = requests.get(URL, headers=headers, timeout=10)

    if response.status_code == 304:
        print("[payloads] Payloads en caché actualizados.")
        return

    if response.status_code == 200:
        print("[payloads] Nueva versión detectada. Actualizando caché...")

        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(response.text)

        etag = response.headers.get("ETag")
        if etag:
            with open(ETAG_FILE, "w") as f:
                f.write(etag)

        print("[payloads] Caché actualizado.")
    else:
        raise RuntimeError(f"Error inesperado al descargar payloads: {response.status_code}")


def load_payloads():
    """Carga los payloads desde el archivo JSON en caché.

    Debe llamarse después de `download_if_updated`.
    """
    if not os.path.exists(CACHE_FILE):
        raise FileNotFoundError(
            f"El archivo de caché {CACHE_FILE} no existe. Asegúrate de ejecutar download_if_updated() primero."
        )

    with open(CACHE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def get_payload_by_id(payloads, payload_id):
    """Retorna un payload específico por su ID."""
    for p in payloads:
        if p.get("id") == payload_id:
            return p
    return None


def get_detection_payloads(payloads):
    """Filtra y retorna solo los payloads de tipo detección.

    Se asume que el JSON tiene un campo "type" o similar. Ajusta el filtro
    según la estructura real de tus payloads.
    """
    # Ejemplo genérico: payloads que tengan campo "category" == "detection"
    detection_payloads = []
    for p in payloads:
        category = p.get("category") or p.get("type")
        if category and str(category).lower() == "detection":
            detection_payloads.append(p)
    return detection_payloads
