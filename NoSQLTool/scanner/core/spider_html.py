# scanner/core/spider_html.py
import re
import requests
from urllib.parse import urljoin, urlparse
from collections import deque

class HTMLSpider:
    def __init__(self, base_url, max_depth=2, timeout=5):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.timeout = timeout
        self.visited = set()
        self.session = requests.Session()

    def extract_links(self, html):
        pattern = r'href=[\'"]?([^\'" >]+)'
        return re.findall(pattern, html)

    def crawl(self):
        queue = deque([(self.base_url, 0)])
        found = set()

        while queue:
            url, depth = queue.pop()
            if depth > self.max_depth or url in self.visited:
                continue

            self.visited.add(url)

            try:
                r = self.session.get(url, timeout=self.timeout)
            except:
                continue

            if "text/html" in r.headers.get("Content-Type", ""):
                links = self.extract_links(r.text)

                for link in links:
                    absolute = urljoin(url, link)
                    parsed = urlparse(absolute)

                    found.add(parsed.path)

                    if absolute not in self.visited:
                        queue.appendleft((absolute, depth + 1))

        return found
