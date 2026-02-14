# Changelog
All notable changes to **AegisCLI** will be documented in this file.

The format is based on [Semantic Versioning](https://semver.org/).

---

## [0.3.0] - 2026-02-15
### Added
- New Profiler submodule: **Web Fingerprinter**
  - Connection analysis (status code, timing, HTTP version, redirect chains)
  - SSL/TLS certificate inspection (subject, issuer, expiry, SANs with smart truncation)
  - HTTP header profiling with security-focused analysis
  - Cookie parsing with detailed attribute extraction
- Centralized text formatting system via `core/helpers/formatter.py`
  - Consistent color-coded terminal output across modules
  - Smart truncation for long data lists (certificates, DNS records, etc.)

### Changed
- Restructured project layout: moved `logger.py` and `flagger.py` to `core/utils/`
- Improved output readability with unified formatting utilities

### Known Issues
- WHOIS and DNS submodules still use legacy formatting (migration to formatter.py planned for v0.3.1a0)
- Verbose mode is not in Web Fingerprinter as the flag will be meeting improvements (planned in v0.3.2a0)

---

## [0.2.0] - 2026-02-05
### Added
- New Profiler submodule was added - DNS Resolver.
- Reverse DNS lookup integration.
- Verbose mode (`-v`) with step-by-step logging.
- Added `dnspython` as a dependency.

### Changed
- Structure changed for better maintance
- Commands structure changed

### Fixed
- Minor consistency changes

---

## [0.1.0] - 2026-01-29
### Added
- Initial project structure.
- WHOIS submodule for **Profiler** module.
- CLI entry point `aegiscli`.
- Logging was added

