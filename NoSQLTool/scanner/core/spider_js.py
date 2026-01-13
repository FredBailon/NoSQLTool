# scanner/core/spider_js.py
import re
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

API_PATTERN = r'["\'](\/[a-zA-Z0-9_\-\/]+)["\']'

class JavaScriptSpider:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def get_js_files(self):
        try:
            html = self.session.get(self.base_url).text
            soup = BeautifulSoup(html, "html.parser")
            return [urljoin(self.base_url, script["src"])
                    for script in soup.find_all("script") if script.get("src")]
        except:
            return []

    def crawl(self):
        endpoints = set()
        js_files = self.get_js_files()

        for js_url in js_files:
            try:
                text = self.session.get(js_url).text
                matches = re.findall(API_PATTERN, text)
                endpoints.update(matches)
            except:
                pass

        return endpoints
