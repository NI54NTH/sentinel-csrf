# Sentinel-CSRF

```
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

 CSRF Exploit Verification Tool | Author: N15H
```

A **verification-driven CSRF exploitation assistant** for VAPT teams and bug bounty hunters. Unlike traditional scanners that flood reports with false positives, Sentinel-CSRF reports only what it can prove.

## 🎯 Philosophy

- **Prefer false negatives over false positives**
- **Never report without exploit reasoning**
- **Every finding answers: "Why does the browser allow this?"**

---

## 📦 Installation

### Option 1: pip from PyPI (Easiest)
```bash
pip install sentinel-csrf
```

### Option 2: pipx (Recommended for CLI tools)
```bash
# Install pipx if not already installed
sudo apt install pipx
pipx ensurepath

# Install Sentinel-CSRF
pipx install sentinel-csrf
```

### Option 3: From Source
```bash
git clone https://github.com/NI54NTH/sentinel-csrf.git
cd sentinel-csrf
pip install -e .
```

### Verify Installation
```bash
sentinel-csrf --version
sentinel-csrf --help
```

---

## 🚀 Quick Start

### Basic Scan
```bash
# Scan a request for CSRF vulnerabilities
sentinel-csrf scan -c cookies.txt -r request.txt -o ./results
```

### Generate PoC
```bash
# Generate HTML exploit from request
sentinel-csrf poc generate -r request.txt -o poc.html
```

### Reuse Last Inputs
```bash
# After first scan, reuse cached inputs
sentinel-csrf scan --reuse-last
```

---

## 📖 Complete Command Reference

### Global Options
```bash
sentinel-csrf --help              # Show help
sentinel-csrf --version           # Show version
sentinel-csrf --verbose           # Enable verbose output
```

---

### `scan` - CSRF Vulnerability Scanner

Analyze HTTP requests for exploitable CSRF vulnerabilities.

```bash
sentinel-csrf scan [OPTIONS]
```

#### Input Options (choose one for each)

| Cookie Input | Description |
|--------------|-------------|
| `-c FILE, --cookies FILE` | Path to Netscape cookie file |
| `--cookies-stdin` | Read cookies from STDIN (Ctrl+D to end) |
| `--reuse-last-cookies` | Reuse last cached cookies |
| `--reuse-last` | Reuse both cached request and cookies |

| Request Input | Description |
|---------------|-------------|
| `-r FILE, --request FILE` | Path to raw HTTP request file |
| `--request-stdin` | Read request from STDIN (Ctrl+D to end) |
| `--reuse-last-request` | Reuse last cached request |

#### Output Options

| Option | Description |
|--------|-------------|
| `-o DIR, --output-dir DIR` | Results directory (default: `./csrf-results`) |
| `-f FORMATS, --format FORMATS` | Output formats: `json,markdown` (default: both) |
| `--suppress-informational` | Hide low-confidence findings |
| `--no-cache` | Don't cache inputs after scan |

#### Examples

```bash
# Basic scan with files
sentinel-csrf scan -c cookies.txt -r request.txt

# Scan with STDIN input (paste, then Ctrl+D)
sentinel-csrf scan --request-stdin --cookies-stdin

# Pipe request from clipboard
xclip -o | sentinel-csrf scan --request-stdin -c cookies.txt

# Reuse last scan inputs
sentinel-csrf scan --reuse-last

# Mix: new request with cached cookies
sentinel-csrf scan -r new-request.txt --reuse-last-cookies

# Custom output directory
sentinel-csrf scan -c cookies.txt -r request.txt -o ./my-results
```

---

### `import` - Format Conversion

Convert Burp exports and cookie strings to canonical formats.

#### `import burp` - Burp XML to Raw HTTP

```bash
sentinel-csrf import burp -i burp-export.xml -o ./requests/
```

| Option | Description |
|--------|-------------|
| `-i FILE, --input FILE` | Burp Suite XML export file |
| `-o DIR, --output DIR` | Output directory for request files |

#### `import cookies` - Cookie String to Netscape

```bash
sentinel-csrf import cookies -i "session=abc123; auth=xyz" -d example.com -o cookies.txt
```

| Option | Description |
|--------|-------------|
| `-i STRING, --input STRING` | Cookie string (from browser DevTools) |
| `-d DOMAIN, --domain DOMAIN` | Target domain |
| `-o FILE, --output FILE` | Output Netscape cookie file |

---

### `poc` - Proof-of-Concept Generation

Generate and serve CSRF proof-of-concept HTML files.

#### `poc generate` - Create HTML Exploit

```bash
sentinel-csrf poc generate [OPTIONS] -o OUTPUT
```

| Input Option | Description |
|--------------|-------------|
| `-r FILE, --request FILE` | Raw HTTP request file |
| `-f FILE, --finding FILE` | Finding JSON file from scan |
| `--request-stdin` | Read request from STDIN |

| Option | Description |
|--------|-------------|
| `-o FILE, --output FILE` | Output HTML file (required) |
| `--vector VECTOR` | Attack vector (see below) |

**Attack Vectors:**
| Vector | Description |
|--------|-------------|
| `form_post` | Auto-submitting POST form (default) |
| `form_get` | GET form submission |
| `img_tag` | Silent GET via `<img>` tag |
| `iframe` | Hidden iframe |
| `fetch` | Fetch API request |

```bash
# Generate from request file
sentinel-csrf poc generate -r request.txt -o poc.html

# Generate from STDIN
sentinel-csrf poc generate --request-stdin -o poc.html

# Use specific attack vector
sentinel-csrf poc generate -r request.txt -o poc.html --vector img_tag

# Generate from finding JSON
sentinel-csrf poc generate -f findings.json -o poc.html
```

#### `poc serve` - Local HTTP Server

Serve PoCs for browser testing (required for SameSite=Lax testing).

```bash
sentinel-csrf poc serve -d ./pocs -p 8080
```

| Option | Description |
|--------|-------------|
| `-d DIR, --dir DIR` | PoC directory (default: `./pocs`) |
| `-p PORT, --port PORT` | Port number (default: `8080`) |

---

## 📋 Input File Formats

### Netscape Cookie File (`cookies.txt`)
```
# Netscape HTTP Cookie File
.example.com	TRUE	/	FALSE	0	session_id	abc123
.example.com	TRUE	/	TRUE	0	auth_token	xyz789
```

### Raw HTTP Request (`request.txt`)
```http
POST /api/user/update HTTP/1.1
Host: example.com
Cookie: session_id=abc123
Content-Type: application/x-www-form-urlencoded

email=attacker@evil.com
```

---

## 📊 Output

### Scan Results
```
==================================================
SCAN SUMMARY
==================================================
  Target:            example.com
  Requests Analyzed: 1
  CSRF Candidates:   1

  Confirmed:         0
  Likely:            1
  Informational:     0
  Suppressed:        0
==================================================

FINDINGS:
  🔴 [CSRF-001] CRITICAL: /api/user/update
     Type: form_based, Vector: form_post
```

### Generated Files
- `findings.json` - Machine-readable results
- `report.md` - Human-readable report

---

## 🔍 CSRF Types Detected

| Type | Description |
|------|-------------|
| **Form-based (POST)** | Traditional auto-submitting form |
| **GET-based** | State-changing GET requests |
| **Login CSRF** | Force victim to login as attacker |

---

## 🛡️ What Makes It Different

| Feature | Sentinel-CSRF | Traditional Scanners |
|---------|---------------|---------------------|
| False Positive Rate | <10% | >50% |
| Browser Awareness | ✅ SameSite, CORS | ❌ None |
| Verification | ✅ Proves exploitability | ❌ Flags missing tokens |
| PoC Generation | ✅ Ready-to-use HTML | ❌ Manual |

---

## 📁 Cache Location

Inputs are cached for quick reuse:
```
~/.sentinel-csrf/cache/
├── last-request.txt
└── last-cookies.txt
```

---

## 🔗 Links

- **PyPI**: https://pypi.org/project/sentinel-csrf/
- **Repository**: https://github.com/NI54NTH/sentinel-csrf
- **Author**: N15H

---

## 📄 License

MIT License - Use freely, contribute back!
