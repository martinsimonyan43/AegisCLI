import whoisit
whoisit.bootstrap()
from colorama import Fore, Style
import subprocess
from aegiscli.core.logger import start_log, stop_log, log


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



class Whois:
    def __init__(self, settings, target, advanced):
        self.settings = settings
        self.target = target 
        self.advanced = advanced
        try:
            self.data = whoisit.domain(self.target)
            self.mode = "rdap"
        except:
            self.data = None
            self.mode = None

        if not isinstance(self.data, dict):
            self.raw_whois = whois_shell(self.target)
            if self.raw_whois:
                self.mode = "whois_raw"
            else:
                self.mode = "none"


    def domain_info(self):
        if self.mode == "whois_raw":
            log(f"{Fore.CYAN}[NOTICE] {Style.RESET_ALL}This registry does not support RDAP. WHOIS formatting varies by TLD and may appear inconsistent. Raw WHOIS data is shown exactly as received from the registry.")
            log(f"{Fore.MAGENTA} === DOMAIN INFO === {Style.RESET_ALL}")
            log(self.raw_whois)
            return

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
                "url": registrar[0].get("url")
            },

            "abuse": {
                "email": abuse[0].get("email"),
                "tel": abuse[0].get("tel"),
            },
        }

        def pretty():
            log(f"{Fore.MAGENTA} === DOMAIN INFO === {Style.RESET_ALL}")
            tab = " " * 4

            for key, value in info.items():

                if isinstance(value, dict):
                    log(f"{Fore.BLUE}{key.capitalize()}: {Style.RESET_ALL}")

                    for k, v in value.items():

                        if isinstance(v, dict):
                            if len(v) == 1:
                                # inline
                                only_key = next(iter(v))
                                only_val = v[only_key]
                                log(f"{tab}{k}: {only_key}: {only_val}")
                            else:
                                # multi-line
                                log(f"{tab}{k}:")
                                for kk, vv in v.items():
                                    log(f"{tab*2}{kk}: {vv}")

                        elif isinstance(v, (list, tuple, set)):
                            if len(v) == 1:
                                # inline
                                only = next(iter(v))
                                log(f"{tab}{k}: {only}")
                            else:
                                # multi-line
                                log(f"{tab}{k}:")
                                for item in v:
                                    log(f"{tab*2}{item}")

                        else:
                            log(f"{tab}{k}: {v}")

                elif isinstance(value, (list, tuple, set)):
                    if len(value) == 1:
                        # inline
                        only = next(iter(value))
                        log(f"{Fore.BLUE}{key.capitalize()}: {Style.RESET_ALL} {only}")
                    else:
                        log(f"{Fore.BLUE}{key.capitalize()}: {Style.RESET_ALL}")
                        for item in value:
                            log(f"{tab}{item}")

                else:
                    log(f"{Fore.BLUE}{key.capitalize()}: {Style.RESET_ALL} {value}")

        pretty()


if __name__ == "__main__":
    script = Whois(settings=None, target="emis.am", advanced=False)
    script.domain_info()




