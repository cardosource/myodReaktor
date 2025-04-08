#!/usr/bin/env python3
"""
myodReaktor :: WAF Detection - Open/Closed Principle Implementation
"""
import re
from datetime import datetime
from abc import ABC, abstractmethod

class HTMLAnalyzer(ABC):
    """Interface para análise de conteúdo HTML"""
    @abstractmethod
    def analyze(self, content: str) -> list:
        """Analisa o conteúdo HTML e retorna detecções"""
        pass

class RegexHTMLAnalyzer(HTMLAnalyzer):
    """Implementação concreta usando regex"""
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
    """Scanner de WAF via análise de HTML"""
    def __init__(self, waf_db: dict, analyzer: HTMLAnalyzer = None):
        self.waf_db = waf_db
        self.analyzer = analyzer or RegexHTMLAnalyzer(waf_db)
        self.payloads = [
            "1' OR '1'='1",
            "1' OR 1=1-- -",
            "1' OR 1=1#",
            "1' OR 1=1/*"
        ]
    
    async def scan(self, session, base_url: str) -> list:
        """Executa varredura e retorna lista de WAFs detectados"""
        detected_wafs = []
        
        for payload in self.payloads:
            test_url = f"{base_url}?test={payload}"
            async with session.get(test_url, ssl=False) as response:
                content = await response.text()
                detections = self.analyzer.analyze(content)
                
                for detection in detections:
                    if detection not in detected_wafs:
                        detected_wafs.append(detection)
        
        return detected_wafs
