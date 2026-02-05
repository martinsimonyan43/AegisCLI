from colorama import Fore, Style
from aegiscli.core.logger import log

class Verbose:
    def __init__(self):
        self.enabled = False
        self.level = 0  # simple indentation

    def enable(self):
        self.enabled = True

    def _indent(self):
        return " " * (self.level * 4)

    def write(self, text):
        if self.enabled:
            log(f"{self._indent()}[{Fore.CYAN}*{Style.RESET_ALL}] {text}")

    def step(self, text):
        if self.enabled:
            log(f"{self._indent()}[->] {text}")

    def ok(self, text):
        if self.enabled:
            log(f"{self._indent()}[+] {text}")

    def fail(self, text):
        if self.enabled:
            log(f"{self._indent()}[-] {text}")

    def header(self, text):
        if self.enabled:
            log(f"{self._indent()}[{Fore.CYAN}*{Style.RESET_ALL}] === {text} ===")

    def space(self):
        if self.enabled:
            log("")

    def indent(self):
        self.level += 1

    def unindent(self):
        if self.level > 0:
            self.level -= 1

verbose = Verbose()
