import httpx
import aegiscli.tools.profiler.profiler as profiler
from aegiscli.core.utils.logger import log
from aegiscli.core.utils.flagger import verbose
from colorama import Fore, Style
from aegiscli.core.helpers.formatter import s, parse_value, parse_cookie, flattener
import ssl
import socket


class WebFinger(profiler.Profiler):
    def __init__(self, settings, submodule, mode, target):
        super().__init__(settings, submodule, mode, target)
        self.target = target
        self.domain = self.target.replace("http://", "") if self.target.startswith("http://") else self.target
        self.domain = self.target.replace("https://", "") if self.target.startswith("https://") else self.target
        self.tab = " " * 4
        self.important_headers = [     
            "Server",              # Web server & version (nginx, Apache, Cloudflare…)
            "Date",                # Timestamp of response
            "Content-Type",        # MIME type
            "Content-Length",      # Response size
            "Content-Encoding",    # gzip, br, deflate…
            "Transfer-Encoding",   # chunked, identity…
            "Connection",          # keep-alive / close
            "Set-Cookie",          # Session hints, frameworks, security flags
            "X-Powered-By",        # Framework leaks (PHP, Express, ASP.NET…)
            "X-AspNet-Version",    # ASP.NET version leak
            "X-AspNetMvc-Version", # ASP.NET MVC version leak
            "X-Drupal-Dynamic-Cache",
            "X-Generator",         # Drupal, Joomla, Ghost, etc.
            "Via",                 # Proxies/CDNs
            "CF-RAY",              # Cloudflare fingerprint
            "CF-Cache-Status",     # Cloudflare caching behavior
            "X-Cache",             # Varnish, Nginx cache
            "Strict-Transport-Security", # HSTS enabled?
            "Access-Control-Allow-Origin", # CORS
        ]

        self.response = None
        self.connection_data = {}
        self.headers = {}
        self.important_cert_data = [
            "issuer", "notAfter", "subject", "subjectAltName", "version"
        ]
        self.certs = {}


    def fetch(self):
        if not self.target.startswith("http://") or not self.target.startswith("https://") :
            try:
                self.target = "https://" + self.target
            except Exception:
                self.target = "http://" + self.target

        self.response = httpx.get(url=self.target, timeout=5, follow_redirects=True)

    def connection(self):
        self.connection_data["Status Code"] = self.response.status_code
        self.connection_data["Time Spent"] = self.response.elapsed.total_seconds()
        self.connection_data["HTTP Version"] = self.response.http_version
        chain = [str(r.url) for r in self.response.history] + [str(self.response.url)]
        self.connection_data["Redirects"] = " → ".join(chain)

    def headers_module(self):
        for h in self.important_headers:
            value = self.response.headers.get(h)
            if value and h != "Set-Cookie":
                self.headers[h] = value
        cookies = self.response.headers.get_list("Set-Cookie")
        if cookies:
            self.headers["Set-Cookie"] = [parse_cookie(c) for c in cookies]

    def get_cert(self):
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as sock:
            sock.connect((self.domain, 443))
            raw = sock.getpeercert()
            for key, value in raw.items():
                if key in self.important_cert_data:
                    self.certs[key] = value
            try:
                if self.certs["version"] == 3:
                    del self.certs["version"]
            except:
                pass
        



    def pretty(self):
        s.header("Web Fingerprint")
        s.subheader("Connection")
        s.print_dict(self.connection_data)
        s.subheader("Certificates")
        s.print_dict(flattener(self.certs))
        s.subheader("Headers")
        s.print_dict(self.headers)
        


    def result(self):
        self.fetch()
        self.connection()
        self.headers_module()
        self.get_cert()
        self.pretty()

if __name__ == "__main__":
    w = WebFinger(settings=None, submodule=None, mode=None, target="google.com")
    w.result()

