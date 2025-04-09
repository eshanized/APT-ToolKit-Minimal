# 📍 APT-ToolKit – Development Roadmap

> A step-by-step guide to building the toolkit from core to GUI.

---

## ✅ Phase 1: Core Infrastructure

| Task                                          | Status  |
|-----------------------------------------------|---------|
| Create `src/utils/logger.py`                  | ✅ Done |
| Implement `src/core/engine.py`                | ✅ Done |
| Design `src/core/dispatcher.py`               | ✅ Done  |
| Add `src/utils/helpers.py`                    | ✅ Done  |
| Create `src/utils/config.py`                  | ✅ Done  |
| Add `src/core/plugin_loader.py` *(optional)*  | ✅ Done  |

---

## 🧪 Phase 2: Base Modules & Tests

| Task                                          | Status  |
|-----------------------------------------------|---------|
| Build `src/modules/recon.py`                  | ✅ Done  |
| Build `src/modules/brute_force.py`            | ✅ Done  |
| Create `src/tests/test_recon.py`              | ✅ Done  |
| Build `src/modules/report_gen.py`             | ✅ Done  |

---

## 🖼️ Phase 3: GUI Foundation

| Task                                          | Status  |
|-----------------------------------------------|---------|
| Design `src/ui/main_window.ui`                | ☐ Todo  |
| Design `src/ui/recon.ui`                      | ☐ Todo  |
| Create `src/ui/logs.ui`                       | ☐ Todo  |
| Implement `src/main.py`                       | ☐ Todo  |

---

## 🔄 Phase 4: Module Expansion

| Task                                          | Status  |
|-----------------------------------------------|---------|
| Build `src/modules/vuln_scanner.py`           | ☐ Todo  |
| Build `src/modules/exploit_exec.py`           | ☐ Todo  |
| Build `src/modules/web_scanner.py`            | ☐ Todo  |
| Create corresponding UI files (`.ui`)         | ☐ Todo  |

---

## ⚙️ Phase 5: Utilities & Assets

| Task                                          | Status  |
|-----------------------------------------------|---------|
| Add `src/utils/validators.py`                 | ☐ Todo  |
| Create `src/templates/report_template.html`   | ☐ Todo  |
| Add wordlists to `src/wordlists/`             | ☐ Todo  |
| Write `scripts/run_gui.sh`                    | ✅ Done |
| Write/Update `README.md`                      | ☐ Todo  |

---

## 🌟 Future Enhancements (Optional)

| Feature                                       | Status  |
|-----------------------------------------------|---------|
| Plugin-based architecture (`plugin_loader.py`)| ☐ Todo  |
| Dark mode theme in GUI                        | ☐ Todo  |
| Export report as PDF                          | ☐ Todo  |
| Live terminal embed in UI                     | ☐ Todo  |
| CLI interface for headless mode               | ☐ Todo  |
