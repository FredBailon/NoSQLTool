

import os

GITHUB_RAW_BASE = os.getenv(
    "PAYLOAD_BASE_URL",
    "https://raw.githubusercontent.com/WiloG2/PayloadsNoSQL/refs/heads/main/"
)


CACHE_DIR = os.getenv("CACHE_DIR", ".cache/payloads")

FETCH_TIMEOUT = int(os.getenv("FETCH_TIMEOUT", "5"))
