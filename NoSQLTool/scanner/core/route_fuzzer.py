# scanner/core/route_fuzzer.py
import requests

COMMON_ENDPOINTS = [
    "/users", "/user", "/auth/login", "/auth/register",
    "/api/users", "/api/login", "/api/register",
    "/items", "/products", "/orders", "/clients",
    "/v1/users", "/v1/auth/login"
]

class RouteFuzzer:
    def __init__(self, base_url, timeout=3):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def fuzz(self):
        found = set()
        for ep in COMMON_ENDPOINTS:
            url = self.base_url + ep
            try:
                r = requests.get(url, timeout=self.timeout)
                if r.status_code < 500:  
                    found.add(ep)
            except:
                pass
        return found
