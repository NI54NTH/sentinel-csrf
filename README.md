# Sentinel-CSRF

A verification-driven CSRF exploitation assistant for VAPT teams and bug bounty hunters.

## Features

- **Verification-first**: Reports only exploitable CSRF vulnerabilities
- **False-positive elimination**: Auto-suppresses non-exploitable findings
- **VAPT-ready**: CLI-first design with Burp integration
- **Privacy-focused**: Fully local, no cloud dependencies

## Installation

```bash
pip install -e .
```

## Quick Start

```bash
# Scan for CSRF vulnerabilities
sentinel-csrf scan --cookies cookies.txt --request request.txt

# Import Burp XML export
sentinel-csrf import burp --input burp-export.xml --output ./requests/

# Generate PoC for a finding
sentinel-csrf poc generate --finding finding.json --output poc.html
```

## Documentation

See [PRD.md](PRD.md) for full specifications.

## License

MIT
