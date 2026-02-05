import whoisit
whoisit.bootstrap()
from colorama import Fore, Style
import subprocess
from aegiscli.core.logger import log
import aegiscli.tools.profiler.profiler as profiler
from aegiscli.core.flagger import verbose


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

        verbose.step(f"WHOIS module initialized")
        verbose.step(f"Target: {target}")

        # init internal state
        self.data = None
        self.raw_whois = None

        # attempt RDAP first
        verbose.step("Attempting RDAP lookup...")
        try:
            self.data = whoisit.domain(self.target)

            if isinstance(self.data, dict):
                verbose.ok("RDAP lookup successful")
                self.mode = "rdap"
            else:
                verbose.fail("RDAP returned unexpected format")
                self.mode = None

        except:
            verbose.fail("RDAP lookup failed, falling back to WHOIS")
            self.data = None
            self.mode = None

        # fallback to raw WHOIS
        if not isinstance(self.data, dict):
            verbose.step("Running raw WHOIS query...")

            self.raw_whois = whois_shell(self.target)

            if self.raw_whois:
                verbose.ok("Raw WHOIS query returned data")
                self.mode = "whois_raw"
            else:
                verbose.fail("Raw WHOIS query failed")
                self.mode = "none"
   


    def domain_info(self):

        # CASE 1: Raw WHOIS fallback
        if self.mode == "whois_raw":
            verbose.step("RDAP unavailable, using raw WHOIS output")
            log(f"{Fore.CYAN}[NOTICE]{Style.RESET_ALL} This registry does not support RDAP.")
            log(f"{Fore.MAGENTA} === WHOIS INFO === {Style.RESET_ALL}")
            log(self.raw_whois)
            return

        # CASE 2: No WHOIS at all
        if self.mode == "none":
            verbose.fail("No WHOIS or RDAP data available")
            log(f"{Fore.RED}[ERROR] {Style.RESET_ALL}No WHOIS or RDAP data could be retrieved.")
            return
        
        # CASE 3: RDAP data present
        verbose.step("Formatting RDAP data")

        entities = self.data.get("entities", {})
        registrar = entities.get("registrar", [{}])
        abuse = entities.get("abuse", [{}])

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
                "name": registrar[0].get("name"),
                "url": registrar[0].get("url"),
            },

            "abuse": {
                "email": abuse[0].get("email"),
                "tel": abuse[0].get("tel"),
            },
        }

        self._pretty(info)



    def _pretty(self, info):
        verbose.step("Printing WHOIS data")

        log(f"{Fore.MAGENTA} === WHOIS INFO === {Style.RESET_ALL}")
        tab = " " * 4

        for key, value in info.items():

            if isinstance(value, dict):
                log(f"{Fore.BLUE}{key.capitalize()}: {Style.RESET_ALL}")

                for k, v in value.items():
                    if isinstance(v, dict):
                        if len(v) == 1:
                            only_key = next(iter(v))
                            only_val = v[only_key]
                            log(f"{tab}{k}: {only_key}: {only_val}")
                        else:
                            log(f"{tab}{k}:")
                            for kk, vv in v.items():
                                log(f"{tab*2}{kk}: {vv}")

                    elif isinstance(v, (list, tuple, set)):
                        if len(v) == 1:
                            only = next(iter(v))
                            log(f"{tab}{k}: {only}")
                        else:
                            log(f"{tab}{k}:")
                            for item in v:
                                log(f"{tab*2}{item}")

                    else:
                        log(f"{tab}{k}: {v}")


            elif isinstance(value, (list, tuple, set)):
                if len(value) == 1:
                    only = next(iter(value))
                    log(f"{Fore.BLUE}{key.capitalize()}: {Style.RESET_ALL} {only}")
                else:
                    log(f"{Fore.BLUE}{key.capitalize()}: {Style.RESET_ALL}")
                    for item in value:
                        log(f"{tab}{item}")

            else:
                log(f"{Fore.BLUE}{key.capitalize()}: {Style.RESET_ALL} {value}")



if __name__ == "__main__":
    script = Whois(settings=None, target=input("Enter the target: "))
    script.domain_info()
