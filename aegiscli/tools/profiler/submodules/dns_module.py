import dns.resolver
import dns.reversename
import aegiscli.tools.profiler.profiler as profiler
from aegiscli.core.utils.logger import log
from aegiscli.core.utils.flagger import verbose
from colorama import Style, Fore
from aegiscli.core.helpers.formatter import s
import time


class DNS(profiler.Profiler):
    def __init__(self, settings, submodule, mode, target):
        super().__init__(settings, submodule, mode, target)
        self.target = target
        self.rtype = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
        
    def resolve_record(self):
        verbose.step(f"Initializing DNS resolver with Cloudflare (1.1.1.1) and Google (8.8.8.8)")
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        
        verbose.step(f"Querying {len(self.rtype)} record types for {self.target}")
        verbose.indent()
        
        results = {}
        queries_succeeded = 0
        queries_failed = 0
        total_records = 0
        
        for rtype in self.rtype:
            query_start = time.time()
            try:
                answers = resolver.resolve(self.target, rtype)
                query_time = time.time() - query_start
                records = [record.to_text() for record in answers]
                results[rtype] = records
                
                queries_succeeded += 1
                total_records += len(records)
                verbose.write(f"{rtype}: {len(records)} record(s) found ({query_time:.3f}s)")
                
            except dns.resolver.NoAnswer:
                results[rtype] = []
                queries_failed += 1
                verbose.write(f"{rtype}: No records (NOERROR)")
            except dns.resolver.NXDOMAIN:
                results[rtype] = []
                queries_failed += 1
                verbose.fail(f"{rtype}: Domain does not exist (NXDOMAIN)")
            except dns.exception.Timeout:
                results[rtype] = []
                queries_failed += 1
                verbose.fail(f"{rtype}: Query timed out")
            except Exception as e:
                results[rtype] = []
                queries_failed += 1
                verbose.fail(f"{rtype}: {type(e).__name__}")
        
        verbose.unindent()
        verbose.ok(f"DNS queries complete: {queries_succeeded} succeeded, {queries_failed} failed, {total_records} total records")
        
        return results
    
    def reverse_dns(self, ip):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        
        try:
            rev = dns.reversename.from_address(ip)
            answers = resolver.resolve(rev, "PTR")
            ptrs = [record.to_text() for record in answers]
            return ptrs
        except:
            return []
    
    def reverse_all(self, records):
        ips = []
        ips.extend(records.get("A", []))
        ips.extend(records.get("AAAA", []))
        
        if not ips:
            verbose.write("No A or AAAA records to perform reverse DNS on")
            return {}
        
        verbose.step(f"Performing reverse DNS lookups on {len(ips)} IP address(es)")
        verbose.indent()
        
        results = {}
        ptrs_found = 0
        
        for ip in ips:
            lookup_start = time.time()
            ptrs = self.reverse_dns(ip)
            lookup_time = time.time() - lookup_start
            results[ip] = ptrs
            
            if ptrs:
                verbose.write(f"{ip}: {len(ptrs)} PTR record(s) ({lookup_time:.3f}s)")
                ptrs_found += len(ptrs)
            else:
                verbose.write(f"{ip}: No PTR records ({lookup_time:.3f}s)")
        
        verbose.unindent()
        verbose.ok(f"Reverse DNS complete: {ptrs_found} PTR record(s) found")
        
        return results
    
    def result(self):
        verbose.write(f"Starting DNS enumeration for: {self.target}")
        verbose.space()
        overall_start = time.time()
        
        raw = self.resolve_record()
        verbose.space()
        
        # Filter out empty records for cleaner output
        dns_records = {k: v for k, v in raw.items() if v}
        verbose.step(f"Filtering results: {len(dns_records)}/{len(raw)} record types have data")
        
        # Transform keys to include " RECORD" suffix for display
        display_records = {f"{k} RECORD": v for k, v in dns_records.items()}
        
        verbose.space()
        
        rev = self.reverse_all(records=raw)
        
        # Filter out IPs with no PTR records
        reverse_results = {ip: ptrs for ip, ptrs in rev.items() if ptrs}
        verbose.step(f"Filtering reverse results: {len(reverse_results)}/{len(rev)} IPs have PTR records")
        
        verbose.space()
        overall_time = time.time() - overall_start
        verbose.ok(f"DNS enumeration completed in {overall_time:.3f}s total")
        verbose.space()
        
        # Display results
        s.header("DNS Info")
        s.subheader("DNS Records")
        if display_records:
            s.print_dict(display_records)
        else:
            log(f"{Fore.YELLOW}No DNS records found{Style.RESET_ALL}")
        
        s.subheader("Reverse DNS")
        if reverse_results:
            s.print_dict(reverse_results)
        else:
            log(f"{Fore.YELLOW}No PTR records found{Style.RESET_ALL}")


if __name__ == "__main__":
    initializator = DNS(settings=None, submodule=None, mode=None, target="google.com")
    initializator.result()