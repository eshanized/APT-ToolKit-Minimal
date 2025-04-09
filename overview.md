## 🗂️ Project Structure Overview

```text
.
├── .venv/                     → Python virtual environment (auto-generated)
├── src/
│   ├── main.py                → Application entry point
│   ├── modules/               → Contains individual penetration testing modules
│   ├── ui/                    → PyQt UI definition files (.ui)
│   ├── utils/                 → Helper utilities used across modules
│   ├── core/                  → Core engine logic and infrastructure
│   ├── templates/             → HTML templates (e.g., reports)
│   ├── wordlists/             → Wordlists for brute force, enum, etc.
│   └── data/                  → Optional folder for runtime/cache data
├── tests/                     → Unit tests for modules
├── scripts/                   → Helper scripts for launching, automation
├── requirements.txt           → Python dependencies
├── README.md                  → Project overview
├── .gitignore                 → Ignore virtual env, cache, etc.
```



## 📄 Detailed File Descriptions

### ✅ `src/main.py`
- **Role:** Entry point for launching the PyQt GUI
- **Features:**
  - Initializes `QApplication`
  - Loads `main_window.ui`
  - Connects UI with backend logic via dispatcher



### 📦 `src/modules/`
Each file is a standalone pentest module.

| File Name                  | Description                                      |
|---------------------------|--------------------------------------------------|
| `recon.py`                | DNS, whois, and port scanning                    |
| `vuln_scanner.py`         | CVE checkers, vulnerability databases            |
| `brute_force.py`          | SSH/FTP/web login brute-force attacks            |
| `payload_gen.py`          | Generate payloads (e.g., reverse shells)         |
| `exploit_exec.py`         | Execute exploits (custom or known)               |
| `report_gen.py`           | Compile scan results into a report               |
| `auth_bypass.py`          | Basic auth bypass techniques (e.g., SQLi)        |
| `web_scanner.py`          | Scan for common web flaws (XSS, LFI, etc.)       |
| `network_mapper.py`       | Discover hosts, open ports, topology             |
| `service_enum.py`         | Banner grabbing, protocol analysis               |
| `scan_engine.py`          | Unified scan runner, used by dispatcher          |



### 🎨 `src/ui/`
UI layout files (editable in Qt Designer)

| File Name             | Description                                      |
|----------------------|--------------------------------------------------|
| `main_window.ui`     | The primary GUI layout with sidebar/menu         |
| `recon.ui`           | Form for recon config & output                   |
| `vuln_scanner.ui`    | Vulnerability scanner options                    |
| `brute_force.ui`     | Input for usernames/passwords/targets            |
| `payload_gen.ui`     | Payload selection and generation settings        |
| `exploit_exec.ui`    | Exploit browser or runner interface              |
| `report.ui`          | View or export reports                           |
| `settings.ui`        | User settings/preferences                        |
| `logs.ui`            | View logs/debug output                           |
| `scan_result.ui`     | Unified scan result view                         |
| `terminal.ui`        | Optional embedded terminal output                |



### 🧠 `src/core/`
Core application logic and backend infrastructure

| File Name             | Description                                      |
|----------------------|--------------------------------------------------|
| `engine.py`          | Manages module execution, thread safety          |
| `dispatcher.py`      | Handles UI signals and routes to modules         |
| `thread_pool.py`     | Manages multithreading for scans                 |
| `scheduler.py`       | Optional: Schedule scans, tasks, updates         |
| `plugin_loader.py`   | Dynamic module loading, plugin architecture      |



### 🔧 `src/utils/`
Reusable utilities and helpers

| File Name             | Description                                      |
|----------------------|--------------------------------------------------|
| `logger.py`          | Centralized logging setup (console + file)       |
| `helpers.py`         | Miscellaneous helpers (string, file, net)        |
| `validators.py`      | Input sanitization and format checking           |
| `config.py`          | Global app configuration/settings handler        |
| `network.py`         | Common network ops (ping, resolve, etc.)         |



### 🧾 `src/templates/`
- `report_template.html`: HTML template for rendering scan reports



### 📁 `src/wordlists/`
Wordlists for brute-force, enumeration, etc.

| File Name             | Description                                      |
|----------------------|--------------------------------------------------|
| `common_passwords.txt`| Default passwords for brute-force attacks        |
| `subdomains.txt`      | Used in recon for subdomain enumeration          |
| `usernames.txt`       | Login attack wordlist                            |



### 🧪 `tests/`
- `test_recon.py`: Unit tests for recon module
- `test_brute_force.py`: Tests for brute-force logic
- `test_vuln_scanner.py`: Tests for vulnerability scanner



### 🖥 `scripts/`
Helper/utility scripts

| File Name             | Description                                      |
|----------------------|--------------------------------------------------|
| `run_gui.sh`         | Launches the GUI using the virtual environment   |



### 📄 Root-Level Files
| File                  | Description                                      |
|-----------------------|--------------------------------------------------|
| `requirements.txt`    | Python dependency list (PyQt6, requests, etc.)   |
| `README.md`           | Project intro, modules list, usage               |
| `.gitignore`          | Ignore `.venv/`, `__pycache__/`, etc.            |
