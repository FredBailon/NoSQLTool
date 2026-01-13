# scanner/core/endpoint_manager.py
class EndpointManager:
    def __init__(self):
        self.endpoints = set()

    def add(self, endpoint):
        if not endpoint.startswith("/"):
            return
        self.endpoints.add(endpoint)

    def bulk_add(self, endpoints):
        for ep in endpoints:
            self.add(ep)

    def list(self):
        return sorted(self.endpoints)
