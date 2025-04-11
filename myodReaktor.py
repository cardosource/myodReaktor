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
from _modules.waf_db_loader import load_waf_db
from _modules.html_analysis import HTMLWAFScanner  
print(BANNER())

async def main(url):
    waf_db = load_waf_db()

    detector = WAFDetector(
        waf_db=waf_db,
        detection_strategy=DefaultWAFDetection(),
        scanner_strategy=HTMLWAFScanner(waf_db)
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
            "timestamp": results.get("timestamp")
        }
    }
    
    print(json.dumps(final_output, indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='WAF Detection Tool')
    parser.add_argument('-u', '--url', required=True, help='URL to analyze')
    args = parser.parse_args()
    
    asyncio.run(main(args.url))

