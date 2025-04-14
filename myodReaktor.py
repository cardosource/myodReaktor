#!/usr/bin/env python3
"""
myodReaktor.py - Copyright (C) 2025 Jeferson Cardoso
"""

import asyncio
import aiohttp
import json
import argparse
from datetime import datetime
from _modules.banner import BANNER
from essentialConfig.core import WAFDetector
from _modules.analysisheader import DefaultWAFDetection
from _modules.http2_analysis import DefaultHTTP2Analysis  
from _modules.composite_detection import CompositeDetection
from _modules.waf_db_loader import load_waf_db
from _modules.html_analysis import HTMLWAFScanner
from _modules.ssl_analysis import PassiveSSLDetection 

print(BANNER())

async def main(url):
    waf_db = load_waf_db()
    ssl_detector = PassiveSSLDetection(waf_db)
    detector = WAFDetector(
        waf_db=waf_db,
        detection_strategy=CompositeDetection([
            DefaultHTTP2Analysis(),
            DefaultWAFDetection()]),
        scanner_strategy=HTMLWAFScanner(waf_db),
        ssl_detector=ssl_detector  
    )

    results = await detector.detect_waf(url)

    final_output = {
        "target": url,
        "timestamp": datetime.now().isoformat(),
        "html_analysis": {
            "detected_wafs": results.get("html_waf_detections", [])
        },
        "stealth_analysis": {
            "waf_detected": results.get("waf_detected"),
            "waf_name": results.get("waf_name"),
            "confidence": results.get("confidence"),
            "evidence": results.get("evidence"),
            "blocked": results.get("blocked"),
            "status_code": results.get("status_code"),
            "timestamp": results.get("timestamp"),
            "protocol_analysis": {
                "http_version": results.get("http_version", "1.1"),
                "http2_detected": results.get("http2_detected", False),
                "http2_evidence": results.get("http2_evidence"),
                "http2_confidence": results.get("http2_confidence", 0)
            }
        },
        "ssl_analysis": results.get("ssl_analysis", {})
    }
    
    print(json.dumps(final_output, indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='WAF Detection Tool')
    parser.add_argument('-u', '--url', required=True, help='URL to analyze')
    args = parser.parse_args()
    
    asyncio.run(main(args.url))
