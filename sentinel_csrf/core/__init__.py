"""
Core detection and verification engine.

Provides the main CSRF detection pipeline.
"""

from sentinel_csrf.core.detector import (
    Severity,
    Confidence,
    CsrfType,
    CsrfFinding,
    DetectionResult,
    CsrfDetector,
    detect_csrf,
)

from sentinel_csrf.core.scanner import (
    ScanResult,
    CsrfScanner,
    scan_for_csrf,
)

from sentinel_csrf.core.verifier import (
    ReplayResult,
    ReplayResponse,
    CrossOriginReplayer,
    replay_for_csrf,
    verify_csrf_exploitable,
)

__all__ = [
    # Detector
    "Severity",
    "Confidence",
    "CsrfType",
    "CsrfFinding",
    "DetectionResult",
    "CsrfDetector",
    "detect_csrf",
    # Scanner
    "ScanResult",
    "CsrfScanner",
    "scan_for_csrf",
    # Verifier
    "ReplayResult",
    "ReplayResponse",
    "CrossOriginReplayer",
    "replay_for_csrf",
    "verify_csrf_exploitable",
]
