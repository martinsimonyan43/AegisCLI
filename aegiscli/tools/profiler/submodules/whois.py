import whoisit
whoisit.bootstrap()
from colorama import Fore, Style
import subprocess
from aegiscli.core.utils.logger import log
from aegiscli.core.utils.flagger import verbose
import aegiscli.tools.profiler.profiler as profiler
from aegiscli.core.helpers.formatter import s
import time


def whois_shell(domain):
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=8
        )
        return result.stdout
    except:
        return None


class Whois(profiler.Profiler):
    def __init__(self, settings, submodule, mode, target):
        super().__init__(settings, submodule, mode, target)
        
        verbose.write(f"Initializing WHOIS lookup for: {self.target}")
        verbose.space()
        
        # init internal state
        self.data = None
        self.raw_whois = None
        
        # attempt RDAP first
        verbose.step("Attempting RDAP query (modern protocol)")
        rdap_start = time.time()
        
        try:
            self.data = whoisit.domain(self.target)
            rdap_time = time.time() - rdap_start
            
            if isinstance(self.data, dict):
                self.mode = "rdap"
                verbose.ok(f"RDAP response received ({rdap_time:.3f}s)")
                verbose.write(f"Data structure validated: {len(self.data)} top-level keys")
            else:
                verbose.fail(f"RDAP returned invalid data type: {type(self.data).__name__}")
                self.mode = None
        except ConnectionError:
            verbose.fail("RDAP connection refused or timed out")
            self.data = None
            self.mode = None
        except Exception as e:
            verbose.fail(f"RDAP query failed: {type(e).__name__}")
            self.data = None
            self.mode = None
        
        verbose.space()
        
        # fallback to raw WHOIS
        if not isinstance(self.data, dict):
            verbose.step("Falling back to legacy WHOIS protocol")
            whois_start = time.time()
            
            self.raw_whois = whois_shell(self.target)
            whois_time = time.time() - whois_start
            
            if self.raw_whois:
                self.mode = "whois_raw"
                verbose.ok(f"Raw WHOIS data retrieved ({whois_time:.3f}s)")
                verbose.write(f"Response size: {len(self.raw_whois)} bytes")
            else:
                self.mode = "none"
                verbose.fail("WHOIS command failed or returned no data")
        
        verbose.space()

    def domain_info(self):
        # CASE 1: Raw WHOIS fallback
        if self.mode == "whois_raw":
            s.header("whois info")
            log(f"{Fore.CYAN}[NOTICE]{Style.RESET_ALL} This registry does not support RDAP. This is all we could get\n")
            log(self.raw_whois)
            return
        
        # CASE 2: No WHOIS at all
        if self.mode == "none":
            verbose.fail("No data available from any source")
            log(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No WHOIS or RDAP data could be retrieved.")
            return
        
        # CASE 3: RDAP data present
        verbose.step("Parsing RDAP response structure")
        
        entities = self.data.get("entities", {})
        verbose.write(f"Found {len(entities)} entity type(s) in response")
        
        # Parse entities
        verbose.indent()
        registrar = entities.get("registrar", [{}])
        if registrar and registrar[0]:
            verbose.write("Registrar entity present")
        else:
            verbose.write("⚠ Registrar entity missing")
            
        abuse = entities.get("abuse", [{}])
        if abuse and abuse[0]:
            verbose.write("Abuse contact present")
        else:
            verbose.write("⚠ Abuse contact missing")
        verbose.unindent()
        
        # Build info dict
        info = {
            "name": self.data.get("name"),
            "handle": self.data.get("handle"),
            "url": self.data.get("url"),
            "registration_date": self.data.get("registration_date"),
            "last_changed_date": self.data.get("last_changed_date"),
            "expiration_date": self.data.get("expiration_date"),
            "nameservers": self.data.get("nameservers"),
            "status": self.data.get("status"),
            "dnssec": self.data.get("dnssec"),
            "registrar": {
                "name": registrar[0].get("name") if registrar else None,
                "url": registrar[0].get("url") if registrar else None,
            },
            "abuse": {
                "email": abuse[0].get("email") if abuse else None,
                "tel": abuse[0].get("tel") if abuse else None,
            },
        }
        
        # Count populated fields
        flat_fields = []
        for key, val in info.items():
            if isinstance(val, dict):
                flat_fields.extend([f"{key}.{k}" for k, v in val.items() if v is not None])
            elif val is not None:
                flat_fields.append(key)
        
        verbose.ok(f"Extracted {len(flat_fields)} populated fields from RDAP")
        verbose.space()
        
        s.header("whois info")
        s.print_dict(info)


if __name__ == "__main__":
    script = Whois(settings=None, submodule=None, mode=None, target=input("Enter the target: "))
    script.domain_info()