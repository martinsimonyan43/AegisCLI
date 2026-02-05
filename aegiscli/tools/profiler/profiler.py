class Profiler:
    def __init__(self, settings, submodule, mode, target):
        self.submodule = submodule
        self.mode = mode
        self.target = target
        self.settings = settings

    def selector(self):
        if self.submodule == 'whois':
            import aegiscli.tools.profiler.submodules.whois as whois
            script = whois.Whois(
                settings=self.settings,
                submodule=self.submodule,
                mode=self.mode,
                target=self.target
            )
            script.domain_info()
        elif self.submodule == 'dns':
            import aegiscli.tools.profiler.submodules.dns_module as dns_module
            script = dns_module.DNS(
                settings=self.settings,
                submodule=self.submodule,
                mode=self.mode,
                target=self.target
            )
            script.result()
