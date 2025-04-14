#!/usr/bin/env python3

from typing import List, Dict, Any
from _modules.compatibility import ResponseWrapper

class CompositeDetection:
    def __init__(self, strategies: list):
        self.strategies = strategies
    
    async def check_waf(self, response: ResponseWrapper, waf_db: Dict[str, Any]) -> Dict[str, Any]:
        last_result = None
        
        for strategy in self.strategies:
            try:
                result = await strategy.check_waf(response, waf_db)
                if result['detected']:
                    return result
                    
                last_result = result
                
            except Exception as e:
                continue
                
        return last_result or {
            'detected': False,
            'name': None,
            'confidence': 0,
            'evidence': None,
            'blocked': False,
            'status_code': response.status,
            'http_version': getattr(response, 'http_version', '1.1'),
            'http2_detected': False,
            'http2_evidence': None,
            'http2_confidence': 0
        }
