"""
Sentinel-CSRF Command Line Interface.

This module implements the CLI using argparse for a dependency-free,
audit-friendly interface.
"""

import argparse
import sys
from pathlib import Path

from sentinel_csrf import __version__, __author__


# ASCII Art Banner
BANNER = r"""
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
"""


def print_banner():
    """Print the tool banner with version and author info."""
    print(BANNER)
    print(f" Sentinel-CSRF v{__version__} | CSRF Exploit Verification")
    print(f" Author: {__author__}")
    print()


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="sentinel-csrf",
        description="Sentinel-CSRF: A verification-driven CSRF exploitation assistant",
        epilog="For more information, see: https://github.com/sentinel-csrf/sentinel-csrf",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"sentinel-csrf {__version__}",
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    # Create subparsers for commands
    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="Available commands",
        metavar="<command>",
    )
    
    # === SCAN Command ===
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan for CSRF vulnerabilities",
        description="Analyze HTTP requests for exploitable CSRF vulnerabilities",
    )
    
    # Standalone --reuse-last flag (bypasses both groups)
    scan_parser.add_argument(
        "-L", "--reuse-last",
        action="store_true",
        help="Reuse both last cached request and cookies",
    )
    
    # Cookie input options
    scan_parser.add_argument(
        "-c", "--cookies",
        type=Path,
        metavar="FILE",
        help="Path to Netscape cookie file",
    )
    scan_parser.add_argument(
        "-C", "--cookies-stdin",
        action="store_true",
        help="Read cookies from STDIN (Ctrl+D to end)",
    )
    scan_parser.add_argument(
        "--reuse-last-cookies",
        action="store_true",
        help="Reuse last cached cookies",
    )
    
    # Request input options
    scan_parser.add_argument(
        "-r", "--request",
        type=Path,
        metavar="FILE",
        help="Path to raw HTTP request file",
    )
    scan_parser.add_argument(
        "-R", "--request-stdin",
        action="store_true",
        help="Read raw HTTP request from STDIN (Ctrl+D to end)",
    )
    scan_parser.add_argument(
        "--reuse-last-request",
        action="store_true",
        help="Reuse last cached request",
    )
    
    scan_parser.add_argument(
        "-o", "--output-dir",
        type=Path,
        default=Path("./csrf-results"),
        metavar="DIR",
        help="Directory for results (default: ./csrf-results)",
    )
    scan_parser.add_argument(
        "-f", "--format",
        type=str,
        default="json,markdown",
        metavar="FORMATS",
        help="Output formats: json,markdown,html (default: json,markdown)",
    )
    scan_parser.add_argument(
        "--suppress-informational",
        action="store_true",
        help="Hide low-confidence findings",
    )
    scan_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Do not cache inputs after scan",
    )
    
    # === IMPORT Command ===
    import_parser = subparsers.add_parser(
        "import",
        help="Import and convert request/cookie formats",
        description="Convert Burp exports or cookie strings to canonical formats",
    )
    import_subparsers = import_parser.add_subparsers(
        dest="import_type",
        title="import types",
        metavar="<type>",
    )
    
    # import burp
    burp_parser = import_subparsers.add_parser(
        "burp",
        help="Import Burp XML export",
    )
    burp_parser.add_argument(
        "-i", "--input",
        type=Path,
        required=True,
        metavar="FILE",
        help="Path to Burp XML export file",
    )
    burp_parser.add_argument(
        "-o", "--output",
        type=Path,
        required=True,
        metavar="DIR",
        help="Output directory for raw HTTP requests",
    )
    
    # import cookies
    cookies_parser = import_subparsers.add_parser(
        "cookies",
        help="Import cookie string to Netscape format",
    )
    cookies_parser.add_argument(
        "-i", "--input",
        type=str,
        required=True,
        metavar="STRING",
        help="Cookie string (e.g., 'session=abc123; auth=xyz')",
    )
    cookies_parser.add_argument(
        "-o", "--output",
        type=Path,
        required=True,
        metavar="FILE",
        help="Output path for Netscape cookie file",
    )
    cookies_parser.add_argument(
        "-d", "--domain",
        type=str,
        required=True,
        metavar="DOMAIN",
        help="Domain for the cookies",
    )
    
    # === POC Command ===
    poc_parser = subparsers.add_parser(
        "poc",
        help="Proof-of-concept generation and management",
        description="Generate and serve CSRF proof-of-concept files",
    )
    poc_subparsers = poc_parser.add_subparsers(
        dest="poc_action",
        title="actions",
        metavar="<action>",
    )
    
    # poc generate
    poc_gen_parser = poc_subparsers.add_parser(
        "generate",
        help="Generate HTML PoC from finding or request",
    )
    poc_gen_group = poc_gen_parser.add_mutually_exclusive_group(required=True)
    poc_gen_group.add_argument(
        "-f", "--finding",
        type=Path,
        metavar="FILE",
        help="Path to finding JSON file",
    )
    poc_gen_group.add_argument(
        "-r", "--request",
        type=Path,
        metavar="FILE",
        help="Path to raw HTTP request file",
    )
    poc_gen_group.add_argument(
        "-R", "--request-stdin",
        action="store_true",
        help="Read raw HTTP request from STDIN",
    )
    poc_gen_parser.add_argument(
        "-o", "--output",
        type=Path,
        required=True,
        metavar="FILE",
        help="Output path for HTML PoC",
    )
    poc_gen_parser.add_argument(
        "-v", "--vector",
        type=str,
        default="form_post",
        choices=["form_post", "form_get", "img_tag", "iframe", "fetch"],
        help="Attack vector: form_post, form_get, img_tag, iframe, fetch (default: form_post)",
    )
    
    # poc serve
    poc_serve_parser = poc_subparsers.add_parser(
        "serve",
        help="Serve PoCs via local HTTP server",
    )
    poc_serve_parser.add_argument(
        "-d", "--dir",
        type=Path,
        default=Path("./pocs"),
        metavar="DIR",
        help="Directory containing PoC files (default: ./pocs)",
    )
    poc_serve_parser.add_argument(
        "-p", "--port",
        type=int,
        default=8080,
        metavar="PORT",
        help="Port to serve on (default: 8080)",
    )
    
    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan command."""
    import sys
    import tempfile
    from sentinel_csrf.utils.cache import (
        cache_request, cache_cookies,
        get_cached_request_path, get_cached_cookies_path,
    )
    from sentinel_csrf.core.scanner import scan_for_csrf
    
    print("[*] Scanning for CSRF vulnerabilities...")
    
    # Validate inputs - need either --reuse-last OR proper combination of cookie+request sources
    has_cookie_input = any([
        getattr(args, 'reuse_last', False),
        getattr(args, 'reuse_last_cookies', False),
        getattr(args, 'cookies_stdin', False),
        args.cookies,
    ])
    has_request_input = any([
        getattr(args, 'reuse_last', False),
        getattr(args, 'reuse_last_request', False),
        getattr(args, 'request_stdin', False),
        args.request,
    ])
    
    if not has_cookie_input:
        print("[!] Error: Cookie input required. Use -c FILE, --cookies-stdin, --reuse-last-cookies, or --reuse-last")
        return 1
    if not has_request_input:
        print("[!] Error: Request input required. Use -r FILE, --request-stdin, --reuse-last-request, or --reuse-last")
        return 1
    
    # Resolve cookie input
    cookie_file = None
    cookies_content = None
    
    if getattr(args, 'reuse_last', False):
        # --reuse-last: use both cached inputs
        cookie_file = get_cached_cookies_path()
        if not cookie_file:
            print("[!] Error: No cached cookies found. Run a scan with -c first.")
            return 1
        print(f"    Cookies: {cookie_file} (cached)")
    elif getattr(args, 'reuse_last_cookies', False):
        cookie_file = get_cached_cookies_path()
        if not cookie_file:
            print("[!] Error: No cached cookies found.")
            return 1
        print(f"    Cookies: {cookie_file} (cached)")
    elif getattr(args, 'cookies_stdin', False):
        print("    Cookies: [reading from STDIN, Ctrl+D to end]")
        cookies_content = sys.stdin.read()
        # Write to temp file for scanner
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        tmp.write(cookies_content)
        tmp.close()
        cookie_file = Path(tmp.name)
        print(f"    Cookies: {len(cookies_content)} bytes read from STDIN")
    elif args.cookies:
        cookie_file = args.cookies
        if not cookie_file.exists():
            print(f"[!] Error: Cookie file not found: {cookie_file}")
            return 1
        cookies_content = cookie_file.read_text()
        print(f"    Cookies: {cookie_file}")
    
    # Resolve request input
    request_file = None
    request_content = None
    
    if getattr(args, 'reuse_last', False):
        # --reuse-last: use both cached inputs
        request_file = get_cached_request_path()
        if not request_file:
            print("[!] Error: No cached request found. Run a scan with -r first.")
            return 1
        print(f"    Request: {request_file} (cached)")
    elif getattr(args, 'reuse_last_request', False):
        request_file = get_cached_request_path()
        if not request_file:
            print("[!] Error: No cached request found.")
            return 1
        print(f"    Request: {request_file} (cached)")
    elif getattr(args, 'request_stdin', False):
        print("    Request: [reading from STDIN, Ctrl+D to end]")
        request_content = sys.stdin.read()
        # Write to temp file for scanner
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        tmp.write(request_content)
        tmp.close()
        request_file = Path(tmp.name)
        print(f"    Request: {len(request_content)} bytes read from STDIN")
    elif args.request:
        request_file = args.request
        if not request_file.exists():
            print(f"[!] Error: Request file not found: {request_file}")
            return 1
        request_content = request_file.read_text()
        print(f"    Request: {request_file}")
    
    print(f"    Output:  {args.output_dir}")
    print(f"    Formats: {args.format}")
    
    try:
        # Run scan
        result = scan_for_csrf(
            cookie_file=cookie_file,
            request_file=request_file,
            suppress_informational=args.suppress_informational,
        )
        
        # Create output directory
        args.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Output formats
        formats = [f.strip().lower() for f in args.format.split(",")]
        
        # Save JSON
        if "json" in formats:
            json_path = args.output_dir / "findings.json"
            json_path.write_text(result.to_json())
            print(f"[+] JSON report: {json_path}")
        
        # Save Markdown
        if "markdown" in formats:
            md_path = args.output_dir / "report.md"
            md_path.write_text(result.to_markdown())
            print(f"[+] Markdown report: {md_path}")
        
        # Print summary
        print("")
        print("=" * 50)
        print("SCAN SUMMARY")
        print("=" * 50)
        print(f"  Target:            {result.target}")
        print(f"  Requests Analyzed: {result.requests_analyzed}")
        print(f"  CSRF Candidates:   {result.csrf_candidates}")
        print("")
        print(f"  Confirmed:         {result.confirmed_count}")
        print(f"  Likely:            {result.likely_count}")
        print(f"  Informational:     {result.informational_count}")
        print(f"  Suppressed:        {result.suppressed_count}")
        print("=" * 50)
        
        # Print findings
        if result.findings:
            print("")
            print("FINDINGS:")
            for finding in result.findings:
                severity_icon = {
                    "critical": "🔴",
                    "high": "🟠", 
                    "medium": "🟡",
                    "low": "🟢",
                    "info": "⚪",
                }.get(finding.severity.value, "⚪")
                print(f"  {severity_icon} [{finding.id}] {finding.severity.value.upper()}: {finding.endpoint}")
                print(f"     Type: {finding.csrf_type.value}, Vector: {finding.attack_vector.value if finding.attack_vector else 'N/A'}")
        else:
            print("")
            print("[+] No CSRF vulnerabilities detected")
        
        # Cache inputs for reuse (unless --no-cache)
        if not getattr(args, 'no_cache', False):
            if request_content:
                cache_request(request_content)
            elif request_file and not getattr(args, 'reuse_last', False) and not getattr(args, 'reuse_last_request', False):
                cache_request(request_file.read_text())
            
            if cookies_content:
                cache_cookies(cookies_content)
            elif cookie_file and not getattr(args, 'reuse_last', False) and not getattr(args, 'reuse_last_cookies', False):
                cache_cookies(cookie_file.read_text())
            
            print("[*] Inputs cached for reuse (--reuse-last)")
        
        return 0
        
    except Exception as e:
        print(f"[!] Error during scan: {e}")
        import traceback
        traceback.print_exc()
        return 1


def cmd_import_burp(args: argparse.Namespace) -> int:
    """Execute the import burp command."""
    print(f"[*] Importing Burp XML export...")
    print(f"    Input:  {args.input}")
    print(f"    Output: {args.output}")
    
    if not args.input.exists():
        print(f"[!] Error: Burp XML file not found: {args.input}")
        return 1
    
    # Import the Burp parser
    from sentinel_csrf.input.burp import parse_burp_xml
    
    try:
        requests = parse_burp_xml(args.input)
        args.output.mkdir(parents=True, exist_ok=True)
        
        for i, req in enumerate(requests):
            output_file = args.output / f"request_{i+1:03d}.txt"
            output_file.write_text(req)
            print(f"    [+] Saved: {output_file}")
        
        print(f"[+] Successfully imported {len(requests)} requests")
        return 0
    except Exception as e:
        print(f"[!] Error importing Burp XML: {e}")
        return 1


def cmd_import_cookies(args: argparse.Namespace) -> int:
    """Execute the import cookies command."""
    print(f"[*] Converting cookie string to Netscape format...")
    print(f"    Domain: {args.domain}")
    print(f"    Output: {args.output}")
    
    # Import the cookie parser
    from sentinel_csrf.input.cookies import cookie_string_to_netscape
    
    try:
        netscape_content = cookie_string_to_netscape(args.input, args.domain)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(netscape_content)
        
        print(f"[+] Successfully saved Netscape cookie file")
        return 0
    except Exception as e:
        print(f"[!] Error converting cookies: {e}")
        return 1


def cmd_poc_generate(args: argparse.Namespace) -> int:
    """Execute the poc generate command."""
    from sentinel_csrf.output.poc import (
        generate_poc_from_finding_file,
        generate_poc_from_request_file,
    )
    from sentinel_csrf.analysis.browser import AttackVector
    
    # Map vector string to enum
    vector_map = {
        "form_post": AttackVector.FORM_POST,
        "form_get": AttackVector.FORM_GET,
        "img_tag": AttackVector.IMG_TAG,
        "iframe": AttackVector.IFRAME,
        "fetch": AttackVector.FETCH_SIMPLE,
    }
    vector = vector_map.get(args.vector, AttackVector.FORM_POST)
    
    try:
        if args.finding:
            print(f"[*] Generating HTML PoC from finding...")
            print(f"    Finding: {args.finding}")
            print(f"    Output:  {args.output}")
            
            if not args.finding.exists():
                print(f"[!] Error: Finding file not found: {args.finding}")
                return 1
            
            generate_poc_from_finding_file(args.finding, args.output)
            
        elif getattr(args, 'request_stdin', False):
            print(f"[*] Generating HTML PoC from STDIN...")
            print(f"    Request: [reading from STDIN, Ctrl+D to end]")
            import tempfile
            request_content = sys.stdin.read()
            print(f"    Request: {len(request_content)} bytes read")
            print(f"    Vector:  {args.vector}")
            print(f"    Output:  {args.output}")
            
            # Write to temp file for generator
            tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            tmp.write(request_content)
            tmp.close()
            
            generate_poc_from_request_file(Path(tmp.name), args.output, vector)
            
        elif args.request:
            print(f"[*] Generating HTML PoC from request...")
            print(f"    Request: {args.request}")
            print(f"    Vector:  {args.vector}")
            print(f"    Output:  {args.output}")
            
            if not args.request.exists():
                print(f"[!] Error: Request file not found: {args.request}")
                return 1
            
            generate_poc_from_request_file(args.request, args.output, vector)
        
        print(f"[+] PoC generated: {args.output}")
        print(f"[*] Open in browser or use 'sentinel-csrf poc serve' to test")
        return 0
        
    except Exception as e:
        print(f"[!] Error generating PoC: {e}")
        import traceback
        traceback.print_exc()
        return 1


def cmd_poc_serve(args: argparse.Namespace) -> int:
    """Execute the poc serve command."""
    print(f"[*] Starting local PoC server...")
    print(f"    Directory: {args.dir}")
    print(f"    Port:      {args.port}")
    print(f"    URL:       http://127.0.0.1:{args.port}/")
    
    if not args.dir.exists():
        print(f"[!] Error: PoC directory not found: {args.dir}")
        return 1
    
    # Simple HTTP server bound to localhost only
    import http.server
    import socketserver
    import os
    
    os.chdir(args.dir)
    
    handler = http.server.SimpleHTTPRequestHandler
    
    try:
        with socketserver.TCPServer(("127.0.0.1", args.port), handler) as httpd:
            print(f"[+] Serving at http://127.0.0.1:{args.port}/")
            print("[*] Press Ctrl+C to stop")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
    
    return 0


def main() -> int:
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()
    
    # No command provided
    if args.command is None:
        parser.print_help()
        return 0
    
    # Print banner for subcommand execution (not for top-level --help)
    if args.command:
        print_banner()
    
    # Route to appropriate command handler
    if args.command == "scan":
        return cmd_scan(args)
    
    elif args.command == "import":
        if args.import_type == "burp":
            return cmd_import_burp(args)
        elif args.import_type == "cookies":
            return cmd_import_cookies(args)
        else:
            print("[!] Error: Specify import type (burp or cookies)")
            return 1
    
    elif args.command == "poc":
        if args.poc_action == "generate":
            return cmd_poc_generate(args)
        elif args.poc_action == "serve":
            return cmd_poc_serve(args)
        else:
            print("[!] Error: Specify poc action (generate or serve)")
            return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
