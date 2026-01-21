

import os

GITHUB_RAW_BASE = os.getenv(
    "PAYLOAD_BASE_URL",
    "https://raw.githubusercontent.com/WiloG2/PayloadsNoSQL"
)

REPO_COMMIT = os.getenv(
    "PAYLOAD_COMMIT",
    "9d1a3f9fb02d4acbb605d0f48eb1182e4d16821a"
)

CACHE_DIR = os.getenv("CACHE_DIR", ".cache/payloads")

FETCH_TIMEOUT = int(os.getenv("FETCH_TIMEOUT", "5"))
