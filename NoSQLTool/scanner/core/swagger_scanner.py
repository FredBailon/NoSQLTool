# scanner/core/swagger_scanner.py
import requests

SWAGGER_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v1/api-docs"
]

class SwaggerScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def scan(self):
        found = set()

        for path in SWAGGER_PATHS:
            url = self.base_url + path
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200 and "paths" in r.json():
                    for ep in r.json()["paths"].keys():
                        found.add(ep)
            except:
                pass

        return found
