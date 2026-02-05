import dns.resolver
import dns.reversename
import aegiscli.tools.profiler.profiler as profiler
from aegiscli.core.logger import log
from colorama import Style, Fore
from aegiscli.core.flagger import verbose

class DNS(profiler.Profiler):
    def __init__(self, settings, submodule, mode, target):
        super().__init__(settings, submodule, mode, target)
        verbose.step(f"DNS module initialized")
        verbose.step(f"Target: {target}")

        self.target = target
        self.rtype = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
        self.tab = " " * 4


    def resolve_record(self):
        verbose.step("Resolving DNS records...")
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        results = {}

        for rtype in self.rtype:
            verbose.step(f"Querying {rtype} records...")
            try:
                answers = resolver.resolve(self.target, rtype)
                records = [record.to_text() for record in answers]
                verbose.ok(f"{rtype} records found")
                results[rtype] = records
            except:
                verbose.fail(f"{rtype} records not found")
                results[rtype] = []

        return results
    

    def reverse_dns(self, ip):
        verbose.step(f"Reverse lookup: {ip}")
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

        try:
            rev = dns.reversename.from_address(ip)
            answers = resolver.resolve(rev, "PTR")
            ptrs = [record.to_text() for record in answers]

            verbose.ok(f"PTR found for {ip}")
            return ptrs

        except:
            verbose.fail(f"No PTR for {ip}")
            return []


    def reverse_all(self, records):
        verbose.step("Performing reverse DNS lookups...")

        ips = []
        ips.extend(records.get("A", []))
        ips.extend(records.get("AAAA", []))

        results = {}

        for ip in ips:
            results[ip] = self.reverse_dns(ip)

        return results


    def result(self):
        verbose.step("Formatting DNS output...")
        raw = self.resolve_record()

        log(f"{Fore.MAGENTA}=== DNS INFO ==={Style.RESET_ALL}")
        for record, value in raw.items():
            log(f"{Fore.BLUE}{record} RECORDS:{Style.RESET_ALL}")

            if not value:
                log(self.tab + "No Records")
                continue

            unique = sorted(set(value))

            for v in unique:
                log(f"{self.tab}{v}")

        verbose.step("Processing reverse DNS results...")
        rev = self.reverse_all(records=raw)

        log(f"{Fore.BLUE}REVERSE DNS:{Style.RESET_ALL}")
        for ip, ptrs in rev.items():
            if not ptrs:
                log(f"{self.tab}{ip} → No PTR")
            else:
                for p in ptrs:
                    log(f"{self.tab}{ip} → {p}")

        
if __name__ == "__main__":
    initializator = DNS(settings=None, submodule=None, mode=None, target="google.com")
    initializator.result()
