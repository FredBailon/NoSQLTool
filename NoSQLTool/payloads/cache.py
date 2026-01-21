import os
import requests

def download_if_updated(url, cache_file, etag_file, timeout):
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)

    headers = {}
    if os.path.exists(etag_file):
        with open(etag_file, "r") as f:
            headers["If-None-Match"] = f.read().strip()

    response = requests.get(
        url,
        headers=headers,
        timeout=timeout,
        allow_redirects=True
    )

    if response.status_code == 304:
        return False

    if response.status_code != 200:
        raise RuntimeError(f"Error HTTP {response.status_code}")

    with open(cache_file, "w", encoding="utf-8") as f:
        f.write(response.text)

    if etag := response.headers.get("ETag"):
        with open(etag_file, "w") as f:
            f.write(etag)

    return True
