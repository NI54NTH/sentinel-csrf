#!/bin/bash
# =============================================================================
# Sentinel-CSRF v1.0 - Full Walkthrough Demo
# =============================================================================
# This script demonstrates all features of Sentinel-CSRF
# Run from the project root: ./demo.sh
# =============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "=============================================="
echo "   Sentinel-CSRF v1.0 - Walkthrough Demo"
echo "=============================================="
echo -e "${NC}"

# -----------------------------------------------------------------------------
# STEP 0: Setup
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[STEP 0] Setup${NC}"
echo "Creating demo directory..."

DEMO_DIR="./demo-output"
mkdir -p "$DEMO_DIR"
cd "$(dirname "$0")"

# Activate virtual environment
if [ -d ".venv" ]; then
    source .venv/bin/activate
    echo -e "${GREEN}✓ Virtual environment activated${NC}"
else
    echo -e "${RED}✗ Virtual environment not found. Run: python3 -m venv .venv && pip install -e .${NC}"
    exit 1
fi

echo ""

# -----------------------------------------------------------------------------
# STEP 1: Check Installation
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[STEP 1] Verify Installation${NC}"
echo -e "${BLUE}$ sentinel-csrf --version${NC}"
sentinel-csrf --version
echo ""

echo -e "${BLUE}$ sentinel-csrf --help${NC}"
sentinel-csrf --help
echo ""

# -----------------------------------------------------------------------------
# STEP 2: Create Sample Files
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[STEP 2] Create Sample Input Files${NC}"

# Create a vulnerable request (no CSRF token)
cat > "$DEMO_DIR/vulnerable-request.txt" << 'EOF'
POST /api/change-email HTTP/1.1
Host: vulnerable-app.com
Cookie: session=user_session_token_abc123
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

email=attacker@evil.com&confirm=1
EOF
echo -e "${GREEN}✓ Created: $DEMO_DIR/vulnerable-request.txt${NC}"

# Create a protected request (has CSRF token)
cat > "$DEMO_DIR/protected-request.txt" << 'EOF'
POST /api/update-profile HTTP/1.1
Host: secure-app.com
Cookie: session=user_session_token_xyz789
Content-Type: application/x-www-form-urlencoded
Content-Length: 78

name=John&csrf_token=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4
EOF
echo -e "${GREEN}✓ Created: $DEMO_DIR/protected-request.txt${NC}"

# Create cookies file (Netscape format - no strict SameSite)
cat > "$DEMO_DIR/cookies.txt" << 'EOF'
# Netscape HTTP Cookie File
# Cookies for testing (no SameSite = browser defaults to Lax)
.vulnerable-app.com	TRUE	/	FALSE	0	session	user_session_token_abc123
.vulnerable-app.com	TRUE	/	FALSE	0	user_id	12345
EOF
echo -e "${GREEN}✓ Created: $DEMO_DIR/cookies.txt${NC}"

echo ""

# -----------------------------------------------------------------------------
# STEP 3: Import Commands Demo
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[STEP 3] Import Commands${NC}"

echo -e "${BLUE}# Convert cookie string to Netscape format${NC}"
echo -e "${BLUE}$ sentinel-csrf import cookies -i \"auth=xyz; session=abc\" -d example.com -o $DEMO_DIR/converted-cookies.txt${NC}"
sentinel-csrf import cookies -i "auth=xyz; session=abc" -d example.com -o "$DEMO_DIR/converted-cookies.txt"
echo ""
echo "Contents of converted file:"
cat "$DEMO_DIR/converted-cookies.txt"
echo ""

echo -e "${BLUE}# Import Burp Suite XML export${NC}"
echo -e "${BLUE}$ sentinel-csrf import burp -i examples/burp-export.xml -o $DEMO_DIR/burp-requests/${NC}"
sentinel-csrf import burp -i examples/burp-export.xml -o "$DEMO_DIR/burp-requests/"
echo ""

# -----------------------------------------------------------------------------
# STEP 4: Scan for CSRF Vulnerabilities
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[STEP 4] Scan for CSRF Vulnerabilities${NC}"

echo -e "${BLUE}# Scan a VULNERABLE request (no CSRF protection)${NC}"
echo -e "${BLUE}$ sentinel-csrf scan -c $DEMO_DIR/cookies.txt -r $DEMO_DIR/vulnerable-request.txt -o $DEMO_DIR/vuln-scan${NC}"
sentinel-csrf scan -c "$DEMO_DIR/cookies.txt" -r "$DEMO_DIR/vulnerable-request.txt" -o "$DEMO_DIR/vuln-scan"
echo ""

echo "Generated reports:"
ls -la "$DEMO_DIR/vuln-scan/"
echo ""

echo -e "${CYAN}--- JSON Report (findings.json) ---${NC}"
cat "$DEMO_DIR/vuln-scan/findings.json" | head -30
echo "..."
echo ""

# -----------------------------------------------------------------------------
# STEP 5: Scan Protected Request
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[STEP 5] Scan Protected Request (with CSRF token)${NC}"

# Create cookies for protected request
cat > "$DEMO_DIR/protected-cookies.txt" << 'EOF'
# Netscape HTTP Cookie File
.secure-app.com	TRUE	/	FALSE	0	session	user_session_token_xyz789
EOF

echo -e "${BLUE}$ sentinel-csrf scan -c $DEMO_DIR/protected-cookies.txt -r $DEMO_DIR/protected-request.txt -o $DEMO_DIR/protected-scan${NC}"
sentinel-csrf scan -c "$DEMO_DIR/protected-cookies.txt" -r "$DEMO_DIR/protected-request.txt" -o "$DEMO_DIR/protected-scan"
echo ""

# -----------------------------------------------------------------------------
# STEP 6: Generate PoC from Request
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[STEP 6] Generate PoC Exploit${NC}"

echo -e "${BLUE}# Generate PoC from raw HTTP request${NC}"
echo -e "${BLUE}$ sentinel-csrf poc generate -r $DEMO_DIR/vulnerable-request.txt -o $DEMO_DIR/csrf-poc.html --vector form_post${NC}"
sentinel-csrf poc generate -r "$DEMO_DIR/vulnerable-request.txt" -o "$DEMO_DIR/csrf-poc.html" --vector form_post
echo ""

echo -e "${CYAN}--- Generated PoC HTML ---${NC}"
head -50 "$DEMO_DIR/csrf-poc.html"
echo "..."
echo ""

echo -e "${BLUE}# Generate PoC with IMG tag vector (for GET requests)${NC}"
cat > "$DEMO_DIR/get-request.txt" << 'EOF'
GET /api/delete-account?confirm=yes HTTP/1.1
Host: vulnerable-app.com
Cookie: session=user_session_token_abc123
EOF

echo -e "${BLUE}$ sentinel-csrf poc generate -r $DEMO_DIR/get-request.txt -o $DEMO_DIR/csrf-img-poc.html --vector img_tag${NC}"
sentinel-csrf poc generate -r "$DEMO_DIR/get-request.txt" -o "$DEMO_DIR/csrf-img-poc.html" --vector img_tag
echo ""

# -----------------------------------------------------------------------------
# STEP 7: PoC Server (Optional - Interactive)
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[STEP 7] PoC Server${NC}"
echo -e "${BLUE}To serve PoCs locally (for testing with browser):${NC}"
echo ""
echo "  sentinel-csrf poc serve --dir $DEMO_DIR --port 8080"
echo ""
echo "  Then open: http://127.0.0.1:8080/csrf-poc.html"
echo ""

# -----------------------------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------------------------
echo -e "${CYAN}"
echo "=============================================="
echo "   Demo Complete!"
echo "=============================================="
echo -e "${NC}"

echo "Generated files:"
find "$DEMO_DIR" -type f | sort
echo ""

echo -e "${GREEN}Quick Reference:${NC}"
echo ""
echo "  # Scan for CSRF"
echo "  sentinel-csrf scan -c cookies.txt -r request.txt -o ./results"
echo ""
echo "  # Import Burp XML"
echo "  sentinel-csrf import burp -i export.xml -o ./requests"
echo ""
echo "  # Convert cookies"
echo "  sentinel-csrf import cookies -i \"session=abc\" -d target.com -o cookies.txt"
echo ""
echo "  # Generate PoC from request"
echo "  sentinel-csrf poc generate -r request.txt -o poc.html --vector form_post"
echo ""
echo "  # Generate PoC from finding"
echo "  sentinel-csrf poc generate -f finding.json -o poc.html"
echo ""
echo "  # Serve PoCs"
echo "  sentinel-csrf poc serve --dir ./pocs --port 8080"
echo ""

echo -e "${YELLOW}For VAPT/Bug Bounty workflow:${NC}"
echo "  1. Export requests from Burp Suite (XML)"
echo "  2. Import: sentinel-csrf import burp -i export.xml -o ./requests"
echo "  3. Export cookies from browser (Netscape format)"
echo "  4. Scan: sentinel-csrf scan -c cookies.txt -r ./requests/request_001.txt -o ./results"
echo "  5. Generate PoC: sentinel-csrf poc generate -r ./requests/request_001.txt -o poc.html"
echo "  6. Test: Open poc.html in browser while logged into target"
echo ""
