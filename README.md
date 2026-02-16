# ⚔️ AegisCLI — Modular Recon Framework

AegisCLI is a lightweight recon framework designed to eliminate tool-juggling hell. Native implementations with consistent CLI patterns across profiling, scanning, enumeration, and analysis - built for chaining, automation, and maintainability.

---

## 🚨 Current Version: **0.3.1 Alpha**

This release introduces the Web Fingerprinter submodule, centralized text formatting utilities, and improved project structure with better output consistency.

---

## ✨ Features (v0.3.1 Alpha)

### Profiler Module

* **WHOIS / RDAP Lookup** with intelligent fallback
* **DNS Resolver** supporting:
  * A / AAAA
  * MX
  * TXT
  * NS
  * CNAME
  * SOA
* **Reverse DNS (PTR) Lookups**
* **Web Fingerprinter** featuring:
  * Connection analysis (status code, response time, HTTP version, redirect chains)
  * SSL/TLS certificate inspection (subject, issuer, expiry date, Subject Alternative Names)
  * HTTP header profiling (Server, HSTS, cookies, security headers)
  * Cookie parsing with detailed attribute extraction
  * Smart output truncation for long data lists

### Framework Capabilities

* **Verbose Mode (`-v`)**
  Shows step-by-step internal execution for debugging and transparency.
* **Logging (`--log`)**
  Saves timestamped logs under:
  ```
  ~/.aegiscli/logs
  ```
* **Centralized Formatting**
  Consistent color-coded terminal output across all modules via `core/helpers/formatter.py`.
* **Strict modular architecture**
  Each tool is isolated under `aegiscli/tools/<module>/<submodule>`.
* **Consistent CLI interface**
  All commands follow the pattern:
  ```
  aegiscli <module> <submodule> [flags] <target>
  ```
* **Packaged as a Python project**
  Installable with `pip install .` and exposes the `aegiscli` executable.

---

## 🚀 Quick Start

```bash
# WHOIS / RDAP lookup with verbose mode
aegiscli profiler whois -v example.com

# DNS records with logging to ~/.aegiscli/logs
aegiscli profiler dns --log example.com

# DNS records verbose mode + logging 
aegiscli profiler dns -v --log example.com

# Web fingerprinting
aegiscli profiler web --log httpbin.org

# Web fingerprinting with verbose mode and logging
aegiscli profiler web httpbin.org
```

---

## 🧩 Architecture Overview

AegisCLI follows a clean separation-of-concerns model:

```
aegiscli/
  cli                # Command router, argument parsing, global flags
  core/
    utils/            # logger.py, flagger.py (verbose manager)
    helpers/          # formatter.py (text formatting & visualization)
  tools/
    profiler/         # WHOIS, DNS, Web modules
    scanner/          # (planned)
    enumerator/       # (planned)
    analyser/         # (planned)
    injector/         # (planned)
```

Design principles:

* No global mutable state
* Tools never depend on each other's internals
* Uniform interfaces across all modules
* High readability and maintainability
* Predictable output for automation and chaining

---

## 📦 Roadmap

### Short-term

* Add security analysis flags for Web Fingerprinter (missing HSTS, insecure cookies, etc.)
* Additional OSINT sources for Profiler

### Medium-term

* Start Scanner module (ports, services, banners)
* Enumerator module with optional ffuf adapters
* Analyser module (Using external APIs for reconnisance)
* JSON configuration engine
* Tool Chaining


### Long-term

* Plugin ecosystem
* Output profiles (Minimal / JSON / Extended)
* Unified workflow chaining and refinement
* Injector module (SQLi testing, payload logic)
* Log Analyser


---

## 📜 Changelog

Full history available in `CHANGELOG.md`.

Latest changes in **0.3.1 Alpha**:

* Added Web Fingerprinter submodule to Profiler
* Added centralized text formatting via `core/helpers/formatter.py`
* Restructured project: moved logger.py and flagger.py to `core/utils/`
* Improved output consistency and smart truncation for long data lists

---

## ⚖️ License

Licensed under **AGPLv3** to ensure code transparency, enforce openness, and require attribution for derivative work.

---

## 🧠 Project Philosophy

AegisCLI is built intentionally as a **framework**. The priority is long-term stability, modular expansion, and real-world workflow integration.

Core principles:

* Architecture-first development
* Minimize complexity
* Strict readability standards
* Incremental refinement
* Predictable, consistent behavior

---