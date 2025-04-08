#!/usr/bin/env python3
"""
myodReaktor.py -u <url>
"""
import asyncio
import aiohttp
import json
import shutil
import argparse

from datetime import datetime
from _modules.analysisheader import DefaultWAFDetection
from essentialConfig.core import WAFDetector
from _modules.html_analysis import HTMLWAFScanner


async def main(url):
    traditional_detector = WAFDetector(detection_strategy=DefaultWAFDetection())
    waf_db = traditional_detector.waf_db
    traditional_results = await traditional_detector.detect_waf(url)
    async with aiohttp.ClientSession() as session:
        html_scanner = HTMLWAFScanner(waf_db)
        html_results = await html_scanner.scan(session, url)
    final_output = {
        "target": url,
        "timestamp": datetime.now().isoformat(),
        "header_analysis": traditional_results,
        "html_analysis": {
            "detected_wafs": html_results
        }
    } 
    print(json.dumps(final_output, indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='WAF Detection Tool')
    parser.add_argument('-u', '--url', required=True, help='URL to analyze')
    args = parser.parse_args()
    
    asyncio.run(main(args.url))
