#!/usr/bin/env python3
import re
from abc import ABC, abstractmethod
import inspect

async def _maybe_async(func_result):
    if inspect.isawaitable(func_result):
        return await func_result
    return func_result

class HTMLAnalyzer(ABC):
    @abstractmethod
    def analyze(self, content: str) -> list:
        pass

class RegexHTMLAnalyzer(HTMLAnalyzer):
    def __init__(self, waf_db: dict):
        self.waf_db = waf_db
    
    def analyze(self, content: str) -> list:
        detections = []
        for waf_id, waf_data in self.waf_db['wafs'].items():
            if re.search(waf_data['regex'], content, re.IGNORECASE):
                detections.append({
                    'waf': waf_data['name'],
                    'company': waf_data['company'],
                    'evidence': f"Regex: {waf_data['regex']}"
                })
        return detections

class HTMLWAFScanner:
    def __init__(self, waf_db: dict, analyzer: HTMLAnalyzer = None):
        self.waf_db = waf_db
        self.analyzer = analyzer or RegexHTMLAnalyzer(waf_db)
        self.payloads = [
            "1' OR '1'='1",
            "1' OR 1=1-- -",
            "1' OR 1=1#",
            "1' OR 1=1/*"

        ]
    
    async def scan(self, content: str) -> list:
        return   self.analyzer.analyze(content)
    
    def generate_test_urls(self, base_url: str) -> list:
        return [f"{base_url}?test={payload}" for payload in self.payloads]
