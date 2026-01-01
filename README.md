# 🔍 DeepAudit: AI-Powered SAST Scanner (Local LLM)

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python) ![Ollama](https://img.shields.io/badge/Backend-Ollama-orange?style=for-the-badge) ![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</div>

**DeepAudit** is a static application security testing (SAST) tool that leverages local Large Language Models (via Ollama) to analyze source code for vulnerabilities.

Unlike simple "send file to ChatGPT" scripts, DeepAudit is designed for real-world usage with **Sliding Window** context management and **Strict JSON** output enforcement.

## 🔑 Key Features

* **🔒 100% Private:** Your code never leaves your machine. Everything runs locally via Ollama.
* **🪟 Sliding Window Mechanism:** Splits large files into chunks with overlap (default: 20 lines) to ensure vulnerabilities split across chunk boundaries are not missed.
* **📍 Context Aware:** Automatically injects line numbers into the prompt, reducing hallucinated locations.
* **📋 JSON Mode Enforced:** Uses Ollama's native JSON mode to guarantee machine-readable reports.
* **💾 Exportable Reports:** Saves findings to JSON for easy integration with other tools.

## ⚙️ How It Works

1. **Chunking:** The script reads the target file and splits it into manageable parts (default ~150 lines).
2. **Overlap:** Each subsequent chunk includes the last 20 lines of the previous one to maintain context.
3. **Numbering:** Line numbers are embedded directly into the code string sent to the LLM.
4. **Analysis:** The LLM (e.g., `qwen2.5-coder`) analyzes the chunk for SQLi, XSS, RCE, etc.
5. **Aggregation:** Results are deduplicated and presented in the console or saved to a file.

## 📦 Installation

### 1. Prerequisites

Ensure you have [Ollama](https://ollama.com/) installed and running.

### 2. Pull the Model

We recommend `qwen2.5-coder` for the best balance of speed and accuracy in code analysis.

```bash
ollama pull qwen2.5-coder
```

### 3. Setup

Clone the repo and install the request library.

```bash
git clone https://github.com/BengaminButton/Ollama-Code-Scanner.git
cd Ollama-Code-Scanner
pip install requests
```

## 🚀 Usage

Basic scan of a file:

```bash
python DeepAudit.py targets/vulnerable_code.php
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `file` | Path to source file to analyze | (Required) |
| `--model` | Ollama model to use | `qwen2.5-coder` |
| `--output` | Path to save JSON report | None (Console only) |
| `--timeout` | API request timeout (seconds) | 120 |

### Example: Save Report to JSON

```bash
python DeepAudit.py app.py --model dolphin-llama3 --output report.json
```

## 📊 Example Output

```
[*] Target: targets/leaky_db.php
[*] Model: qwen2.5-coder
[*] Split into 1 chunks (Overlap: 20 lines). Starting analysis...

UQBVaJmHPGKBfgpxkBP_0FEIAXQrP7NAEpcaC1uXVvawZno3===========

SCAN COMPLETE. Found 2 unique issues.

============================================================

[TYPE] SQL Injection
[SEVERITY] High
[LINE] 24
[DETAILS] User input $_GET['id'] is concatenated directly into SQL query.

------------------------------

[TYPE] XSS (Reflected)
[SEVERITY] Medium
[LINE] 28
[DETAILS] Variable $name is echoed back without sanitization.

------------------------------

[*] Report saved to report.json
```

## ⚙️ Configuration

You can tweak the chunk size in DeepAudit.py based on your model's context window:

```python
# ~150 lines fits comfortably in 4k-8k context.
# For 32k context models, you can increase this to 500+.
CHUNK_SIZE = 150

# Overlap lines to prevent context loss at boundaries
OVERLAP_LINES = 20
```

## ⚠️ Disclaimer

This tool is for educational purposes and security assessments of code you own or have permission to test. The author is not responsible for any misuse.

**Author:** Benjamin_Button

---

## 📞 Contact & Links

* **Telegram:** [@Bengamin_Button](https://t.me/Bengamin_Button)
* **XillenStealer:** [t.me/XillenStealer](https://t.me/XillenStealer)
* **XillenAdapter:** [t.me/XillenAdapter](https://t.me/XillenAdapter)
* **Forum:** [forum.duty-free.cc](https://forum.duty-free.cc/threads/1763/)
