#!/usr/bin/env python3
"""
myodReaktor :: WAF Detection - Open/Closed Principle Implementation
"""

import re
from abc import ABC, abstractmethod

class WAFDetectionStrategy(ABC):    
    @abstractmethod
    async def check_waf(self, response, waf_db):
        pass

class DefaultWAFDetection(WAFDetectionStrategy):    
    async def check_waf(self, response, waf_db):
        
        content = (await response.text()).lower()
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        detected_waf = None
        max_confidence = 0
        evidence = []
        
        if response.status in waf_db['generic_block_codes']:
            max_confidence = 0.6
            evidence.append(f"Generic code {response.status}")

        for waf_id, waf_data in waf_db['wafs'].items():
            current_confidence = 0
            current_evidence = []
            
            if re.search(waf_data['regex'], content, re.IGNORECASE):
                current_confidence += 0.4
                current_evidence.append(f"Regex '{waf_data['regex']}'")
            
            for header in waf_data['headers']:
                if header in headers:
                    current_confidence += 0.3
                    current_evidence.append(f"Header '{header}'")
            
            if response.status in waf_data['block_codes']:
                current_confidence += 0.3
                current_evidence.append(f"Code {response.status}")
            
            if current_confidence >= 0.7 and current_confidence > max_confidence:
                max_confidence = current_confidence
                detected_waf = waf_data['name']
                evidence = current_evidence

        return {
            'detected': detected_waf is not None,
            'name': detected_waf,
            'confidence': min(max_confidence, 0.95),
            'evidence': " + ".join(evidence),
            'blocked': response.status in waf_db['generic_block_codes'],
            'status_code': response.status
        }
