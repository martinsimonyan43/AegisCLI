# ⚔️ AegisCLI — Modular Recon Framework

AegisCLI is a lightweight, extensible command-line framework for security reconnaissance and OSINT tasks. It is designed with a strict architecture, isolated modules, and predictable output to serve as a reliable foundation for building modern recon workflows.

---

## 🚨 Current Version: **0.2.0**

This release introduces the DNS Profiler module, Reverse DNS lookups, a global verbose system, logging path expansion, and improvements to the project structure.

---

## ✨ Features (v0.2.0)

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

### Framework Capabilities

* **Verbose Mode (`-v`)**
  Shows step-by-step internal execution for debugging and transparency.
* **Logging (`--log`)**
  Saves timestamped logs under:

  ```
  ~/.aegiscli/logs
  ```
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

## 🚀 Usage Examples

```bash
# WHOIS / RDAP lookup with verbose mode
aegiscli profiler whois -v example.com

# DNS records with logging to ~/.aegiscli/logs
aegiscli profiler dns --log example.com

# DNS records verbose mode + logging 
aegiscli profiler dns -v --log example.com
```

---

## 🧩 Architecture Overview

AegisCLI follows a clean separation-of-concerns model:

```
aegiscli/
  cli/                # Command router, argument parsing, global flags
  core/               # Logger, verbose manager, utilities
  tools/
    profiler/         # WHOIS + DNS modules (current)
    scanner/          # (planned)
    enumerator/       # (planned)
    analyser/         # (planned)
    injector/         # (planned)
```

Design principles:

* No global mutable state
* Tools never depend on each other’s internals
* Uniform interfaces across all modules
* High readability and maintainability
* Predictable output for automation and chaining

---

## 📦 Roadmap

### Short-term

* Additional OSINT sources for Profiler
* Start Scanner module (ports, services, banners)
* Enumerator module with optional ffuf/gobuster adapters

### Medium-term

* Analyser module (hash, file, URL intelligence)
* Injector module (SQLi testing, payload logic)
* Unified workflow chaining and refinement

### Long-term

* Plugin ecosystem
* JSON configuration engine
* Output profiles (Minimal / JSON / Extended)

---

## 📜 Changelog

Full history available in `CHANGELOG.md`.

Latest changes in **0.2.0**:

* Added DNS Profiler module
* Added Reverse DNS support
* Added verbose mode (`-v`)
* Added logging output under `~/.aegiscli/logs`
* Updated project structure and command layout

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
