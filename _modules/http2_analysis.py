#!/usr/bin/env python3
from typing import Dict, Any
from abc import ABC, abstractmethod
from _modules.compatibility import ResponseWrapper

class HTTP2DetectionStrategy(ABC):
    @abstractmethod
    async def check_waf(self, response: ResponseWrapper, waf_db: Dict[str, Any]) -> Dict[str, Any]:
        pass

class DefaultHTTP2Analysis(HTTP2DetectionStrategy): 
    
    async def check_waf(self, response: ResponseWrapper, waf_db: Dict[str, Any]) -> Dict[str, Any]:
        base_result = {
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

        if not hasattr(response, 'http_version') or response.http_version != 'h2':
            return base_result

        for waf_id, waf_data in waf_db['wafs'].items():
            for header in waf_data.get('http2_headers', []):
                if header in response.headers:
                    return {
                        **base_result,
                        'detected': True,
                        'name': waf_data['name'],
                        'confidence': 0.85,
                        'evidence': f'HTTP/2 header: {header}',
                        'http2_detected': True,
                        'http2_evidence': f'Header {header} detectado',
                        'http2_confidence': 0.85
                    }

        return base_result
