# scanner/core/smart_detector.py
import json
import requests

class SmartDetector:
    """
    Descubre endpoints reales basándose en:
    - Comportamiento GET/POST
    - Content-Type
    - Cambio de respuesta con body
    - Detección de rutas dinámicas (:db)
    """

    def __init__(self, base_url, timeout=5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def request(self, method, path, json_body=None):
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(
                method,
                url,
                json=json_body,
                timeout=self.timeout
            )
            return {
                "status": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "text": response.text
            }
        except requests.RequestException:
            return None

    def is_json(self, response):
        if not response:
            return False
        try:
            json.loads(response["text"])
            return True
        except Exception:
            return False

    def probe_static(self, path):
        """Detecta si un endpoint estático existe."""

        get_res = self.request("GET", path)
        post_empty = self.request("POST", path)
        post_json = self.request("POST", path, json_body={})

        is_api = False

        # endpoint real devuelve JSON en alguno de los tres
        if self.is_json(get_res) or self.is_json(post_empty) or self.is_json(post_json):
            is_api = True

        # si GET devuelve HTML pero POST devuelve JSON → endpoint POST válido
        if (get_res and "html" in get_res["content_type"]) and self.is_json(post_json):
            is_api = True

        return is_api

    def probe_dynamic(self, base_path, candidates):
        """Detecta endpoints con rutas dinámicas como /search/:db."""
        found = []

        for value in candidates:
            path = f"{base_path}/{value}"
            res = self.request("POST", path, json_body={})

            if res and self.is_json(res):
                found.append(path)

        return found

    def get_couchdb_dbs(self):
        """Obtiene bases CouchDB vía _all_dbs si existe."""
        res = self.request("GET", "/_all_dbs")
        if not res:
            return []
        try:
            return json.loads(res["text"])
        except:
            return []

    def run(self, base_paths):
        """
        base_paths = rutas principales descubiertas por fuzzer o diccionario
        """
        print("\n🔍 Ejecutando Smart Endpoint Detector...")
        final = []

        # obtener bases para buscar rutas dinámicas
        couch_dbs = self.get_couchdb_dbs()
        if couch_dbs:
            print(f"✔ Bases CouchDB detectadas: {couch_dbs}")

        for path in base_paths:
            print(f"\nProbando: {path}")

            # PROBADOR ESTÁTICO
            if self.probe_static(path):
                print(f"   ✔ Endpoint estático REAL: {path}")
                final.append(path)

            # PROBADOR DINÁMICO
            if couch_dbs:
                dynamic = self.probe_dynamic(path, couch_dbs)
                for d in dynamic:
                    print(f"   ✔ Endpoint dinámico REAL: {d}")
                    final.append(d)

        return list(set(final))
