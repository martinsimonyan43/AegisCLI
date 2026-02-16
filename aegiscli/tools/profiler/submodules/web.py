import httpx
import aegiscli.tools.profiler.profiler as profiler
from aegiscli.core.utils.logger import log
from aegiscli.core.utils.flagger import verbose
from colorama import Fore, Style
from aegiscli.core.helpers.formatter import s, parse_value, parse_cookie, flattener
import ssl
import socket
import time


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
        verbose.step("Normalizing target URL")
        
        if not self.target.startswith("http://") and not self.target.startswith("https://"):
            verbose.write("No protocol detected, attempting HTTPS first")
            try:
                self.target = "https://" + self.target
            except Exception:
                verbose.write("HTTPS unavailable, falling back to HTTP")
                self.target = "http://" + self.target

        verbose.step(f"Sending GET request with 5s timeout, redirects enabled")
        start_time = time.time()
        
        try:
            self.response = httpx.get(url=self.target, timeout=5, follow_redirects=True)
            elapsed = time.time() - start_time
            verbose.ok(f"Response received ({elapsed:.3f}s)")
            
            if self.response.history:
                verbose.indent()
                for i, resp in enumerate(self.response.history, 1):
                    verbose.write(f"Hop {i}: {resp.status_code} at {resp.url}")
                verbose.unindent()
                
        except httpx.TimeoutException:
            verbose.fail(f"Request timed out after 5s")
            raise
        except httpx.ConnectError as e:
            verbose.fail(f"Connection refused or DNS failure")
            raise
        except Exception as e:
            verbose.fail(f"Request failed: {type(e).__name__}")
            raise

    def connection(self):
        verbose.step("Extracting connection metadata")
        
        self.connection_data["Status Code"] = self.response.status_code
        self.connection_data["Time Spent"] = self.response.elapsed.total_seconds()
        self.connection_data["HTTP Version"] = self.response.http_version
        
        chain = [str(r.url) for r in self.response.history] + [str(self.response.url)]
        self.connection_data["Redirects"] = " → ".join(chain)
        
        verbose.ok(f"Captured {len(self.connection_data)} connection properties")

    def headers_module(self):
        verbose.step(f"Filtering {len(self.response.headers)} headers against {len(self.important_headers)} patterns")
        
        found_interesting = []
        found_tech = []
        found_security = []
        found_cdn = []
        skipped = 0
        
        verbose.indent()
        
        for h in self.important_headers:
            value = self.response.headers.get(h)
            if value and h != "Set-Cookie":
                self.headers[h] = value
                found_interesting.append(h)
                
                # Categorize without showing values
                if h in ["X-Powered-By", "Server", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"]:
                    found_tech.append(h)
                elif h in ["Strict-Transport-Security", "Access-Control-Allow-Origin"]:
                    found_security.append(h)
                elif h in ["CF-RAY", "CF-Cache-Status", "X-Cache", "Via"]:
                    found_cdn.append(h)
            else:
                skipped += 1
        
        verbose.unindent()
        
        # Summary of what was found, not the values themselves
        if found_tech:
            verbose.write(f"Found {len(found_tech)} tech fingerprint header(s): {', '.join(found_tech)}")
        if found_security:
            verbose.write(f"Found {len(found_security)} security header(s): {', '.join(found_security)}")
        if found_cdn:
            verbose.write(f"Found {len(found_cdn)} CDN/proxy header(s): {', '.join(found_cdn)}")
        
        verbose.write(f"Skipped {skipped} absent headers")
        
        # Cookie parsing
        cookies = self.response.headers.get_list("Set-Cookie")
        if cookies:
            verbose.step(f"Parsing {len(cookies)} Set-Cookie header(s)")
            self.headers["Set-Cookie"] = [parse_cookie(c) for c in cookies]
            
            # Security flag analysis without showing cookie names/values
            cookies_with_httponly = sum(1 for c in self.headers["Set-Cookie"] if c.get("HttpOnly"))
            cookies_with_secure = sum(1 for c in self.headers["Set-Cookie"] if c.get("Secure"))
            cookies_with_samesite = sum(1 for c in self.headers["Set-Cookie"] if c.get("SameSite"))
            
            if cookies_with_httponly < len(cookies):
                verbose.write(f"⚠ {len(cookies) - cookies_with_httponly} cookie(s) missing HttpOnly flag")
            if cookies_with_secure < len(cookies):
                verbose.write(f"⚠ {len(cookies) - cookies_with_secure} cookie(s) missing Secure flag")
            if cookies_with_samesite < len(cookies):
                verbose.write(f"⚠ {len(cookies) - cookies_with_samesite} cookie(s) missing SameSite attribute")
        
        verbose.ok(f"Header extraction complete: {len(found_interesting)} captured")

    def get_cert(self):
        verbose.step(f"Opening SSL socket to {self.domain}:443")
        
        try:
            ctx = ssl.create_default_context()
            
            start_time = time.time()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as sock:
                sock.connect((self.domain, 443))
                handshake_time = time.time() - start_time
                verbose.ok(f"TLS handshake completed ({handshake_time:.3f}s)")
                
                verbose.step("Retrieving peer certificate chain")
                raw = sock.getpeercert()
                
                if not raw:
                    verbose.fail("Server returned no certificate")
                    return
                
                verbose.write(f"Certificate contains {len(raw)} total fields")
                
                # Filter interesting fields
                cert_fields_found = []
                for key, value in raw.items():
                    if key in self.important_cert_data:
                        self.certs[key] = value
                        cert_fields_found.append(key)
                
                # Remove version 3 (standard, not interesting)
                try:
                    if self.certs.get("version") == 3:
                        del self.certs["version"]
                        cert_fields_found.remove("version")
                        verbose.write("Filtered out X.509 v3 (standard)")
                except:
                    pass
                
                verbose.ok(f"Extracted {len(cert_fields_found)} relevant certificate fields")
                
        except ssl.SSLError as e:
            verbose.fail(f"SSL error: {type(e).__name__}")
            raise
        except socket.gaierror:
            verbose.fail(f"DNS lookup failed for {self.domain}")
            raise
        except socket.timeout:
            verbose.fail("SSL handshake timed out")
            raise
        except ConnectionRefusedError:
            verbose.fail("Port 443 not accepting connections")
            raise
        except Exception as e:
            verbose.fail(f"Certificate retrieval failed: {type(e).__name__}")
            raise
        



    def pretty(self):
        s.header("Web Fingerprint")
        s.subheader("Connection")
        s.print_dict(self.connection_data)
        s.subheader("Certificates")
        s.print_dict(flattener(self.certs))
        s.subheader("Headers")
        s.print_dict(self.headers)
        


    def result(self):
        verbose.write(f"Starting fingerprint: {self.target}")
        verbose.space()
        overall_start = time.time()
        
        try:
            self.fetch()
            verbose.space()
            
            self.connection()
            verbose.space()
            
            self.headers_module()
            verbose.space()
            
            self.get_cert()
            verbose.space()
            
            overall_time = time.time() - overall_start
            verbose.ok(f"Scan completed in {overall_time:.3f}s total")
            verbose.space()
            
            self.pretty()
            
        except Exception as e:
            overall_time = time.time() - overall_start
            verbose.fail(f"Scan aborted after {overall_time:.3f}s")
            raise

if __name__ == "__main__":
    w = WebFinger(settings=None, submodule=None, mode=None, target="google.com")
    w.result()