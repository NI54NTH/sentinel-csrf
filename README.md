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

A **verification-driven CSRF exploitation assistant** for VAPT teams and bug bounty hunters. Reports only what it can prove exploitable.

## 📦 Installation

```bash
pip install sentinel-csrf
```

Or with pipx:
```bash
pipx install sentinel-csrf
```

---

## 🚀 Quick Start

### Scan for CSRF
```bash
# Paste request & cookies directly (Ctrl+D to end each)
sentinel-csrf scan -R -C

# Or use files
sentinel-csrf scan -r request.txt -c cookies.txt
```

### Generate PoC
```bash
sentinel-csrf poc generate -R -o poc.html
```

### Reuse Last Scan
```bash
sentinel-csrf scan -L
```

---

## 📖 Command Reference

### `scan` - CSRF Scanner

| Short | Long | Description |
|-------|------|-------------|
| `-R` | `--request-stdin` | Read request from STDIN |
| `-C` | `--cookies-stdin` | Read cookies from STDIN |
| `-L` | `--reuse-last` | Reuse cached inputs |
| `-r` | `--request FILE` | Request file path |
| `-c` | `--cookies FILE` | Cookies file path |
| `-o` | `--output-dir DIR` | Output directory |

**Examples:**
```bash
sentinel-csrf scan -R -C              # Paste both
sentinel-csrf scan -r req.txt -C      # File + STDIN
sentinel-csrf scan -L                  # Reuse last
```

---

### `poc generate` - Create Exploit HTML

| Short | Long | Description |
|-------|------|-------------|
| `-R` | `--request-stdin` | Read request from STDIN |
| `-r` | `--request FILE` | Request file path |
| `-o` | `--output FILE` | Output HTML file |
| `-v` | `--vector` | Attack vector |

**Attack Vectors:**
| Vector | Use Case |
|--------|----------|
| `form_post` | POST requests (default) |
| `form_get` | GET via form |
| `img_tag` | Silent GET via image |
| `iframe` | Hidden iframe |
| `fetch` | JavaScript fetch |

**Examples:**
```bash
sentinel-csrf poc generate -R -o poc.html
sentinel-csrf poc generate -R -o poc.html -v img_tag
sentinel-csrf poc generate -r req.txt -o poc.html -v iframe
```

---

### `poc serve` - Local Test Server

```bash
sentinel-csrf poc serve -d ./pocs -p 8080
```

---

### `import` - Format Conversion

```bash
# Burp XML to raw requests
sentinel-csrf import burp -i export.xml -o ./requests/

# Cookie string to Netscape format
sentinel-csrf import cookies -i "session=abc" -d example.com -o cookies.txt
```

---

## 🔍 CSRF Types Detected

| Type | Detection |
|------|-----------|
| Form-based POST | ✅ |
| GET-based | ✅ |
| Login CSRF | ✅ |
| JSON API | ⚠️ Partial |

---

## 🛡️ Trusted Framework Tokens

Automatically recognized as protected:
- `sesskey` (Moodle)
- `authenticity_token` (Rails)
- `csrfmiddlewaretoken` (Django)
- `__RequestVerificationToken` (ASP.NET)
- `_token` (Laravel)

---

## 🔗 Links

- **PyPI**: https://pypi.org/project/sentinel-csrf/
- **GitHub**: https://github.com/NI54NTH/sentinel-csrf
- **Author**: N15H

---

## 📄 License

MIT License
