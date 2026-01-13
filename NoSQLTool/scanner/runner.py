# scanner/runner.py
from core.spider_html import HTMLSpider
from core.spider_js import JavaScriptSpider
from core.route_fuzzer import RouteFuzzer
from core.swagger_scanner import SwaggerScanner
from core.endpoint_manager import EndpointManager
from core.smart_detector import SmartDetector

class EndpointDiscoveryRunner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.manager = EndpointManager()

    def run(self):
        print("\n🔍 Iniciando descubrimiento de endpoints...")

        # --- HTML Spider ---
        html = HTMLSpider(self.base_url).crawl()
        print("📌 HTML Spider:", html)
        self.manager.bulk_add(html)

        # --- JS Spider ---
        js = JavaScriptSpider(self.base_url).crawl()
        print("📌 JS Spider:", js)
        self.manager.bulk_add(js)

        # --- Fuzzer ---
        fuzz = RouteFuzzer(self.base_url).fuzz()
        print("📌 Fuzzer:", fuzz)
        self.manager.bulk_add(fuzz)

        # --- Swagger ---
        swagger = SwaggerScanner(self.base_url).scan()
        print("📌 Swagger:", swagger)
        self.manager.bulk_add(swagger)

        # --- SMART DETECTOR ---
        print("\n🤖 Ejecutando Smart Detector...")

        smart = SmartDetector(self.base_url)

        seeds = [
            "/search",      # será expandido a /search/<db>
            "/search-by",
            "/seed",
            "/users",
            "/login",
            "/api"
        ]

        smart_results = smart.run(seeds)

        print("📌 SmartDetector encontró:", smart_results)

        # Agregar los detectados por smart detector
        self.manager.bulk_add(smart_results)

        # --- RESULTADOS FINALES ---
        print("\n🎯 ENDPOINTS FINALES DESCUBIERTOS:")
        for ep in self.manager.list():
            print(" →", ep)

        return self.manager.list()
