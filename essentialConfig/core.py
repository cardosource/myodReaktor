#!/usr/bin/env python3
"""
myodReaktor ::  WAF Detection Core

"""

import json
from datetime import datetime
from typing import List, Dict, Any
from _modules.request_handler import RequestHandler, RequestError
from _modules.mensagem import ProgressoVertical
from _modules.waf_db_loader import load_waf_db
from _modules.ssl_analysis import PassiveSSLDetection
from _modules.composite_detection import CompositeDetection
from _modules.http2_analysis import DefaultHTTP2Analysis
from _modules.analysisheader import DefaultWAFDetection

class WAFDetector:
    def __init__(self, waf_db: Dict[str, Any] = None,
                 detection_strategy: Any = None,
                 mensagem_strategy: Any = None,
                 scanner_strategy: Any = None,
                 ssl_detector: Any = None):
        self.waf_db = waf_db or load_waf_db()
        self._initialize_results()
        self.detection_strategy = detection_strategy or CompositeDetection([
            DefaultHTTP2Analysis(),
            DefaultWAFDetection() 
        ])
        self.mensagem_strategy = mensagem_strategy or ProgressoVertical()
        self.scanner_strategy = scanner_strategy
        self.ssl_detector = ssl_detector or PassiveSSLDetection(self.waf_db)

    def _initialize_results(self) -> None:
        self.results = {
            'target': None,
            'waf_detected': False,
            'waf_name': None,
            'confidence': 0,
            'evidence': None,
            'blocked': False,
            'status_code': None,
            'timestamp': None,
            'html_waf_detections': [],
            'ssl_analysis': None,
            'ssl_waf_detection': None,
            'protocol_analysis': {
                'http_version': '1.1',
                'http2_detected': False,
                'http2_evidence': None,
                'http2_confidence': 0
            }
        }

    async def _fetch_html_content(self, url: str, handler: RequestHandler) -> str:
        try:
            response, _ = await handler.get(url)
            content = await response.text()
            if not content:
                raise RequestError("Empty content received")
            return content
        except Exception as e:
            raise Exception(f"Content fetch failed: {str(e)}")

    async def _process_html_detections(self, url: str, handler: RequestHandler) -> List[Dict[str, Any]]:
        if not self.scanner_strategy:
            return []

        detected_wafs = []
        html_scanner = self.scanner_strategy
        
        try:
            content = await self._fetch_html_content(url, handler)
            initial_detections = await html_scanner.scan(content)
            detected_wafs.extend(initial_detections)

            if not detected_wafs:
                for test_url in html_scanner.generate_test_urls(url):
                    try:
                        test_content = await self._fetch_html_content(test_url, handler)
                        payload_detections = await html_scanner.scan(test_content)
                        detected_wafs.extend(payload_detections)
                    except Exception:
                        continue

            unique_detections = []
            seen = set()
            for d in detected_wafs:
                if d['waf'] not in seen:
                    seen.add(d['waf'])
                    unique_detections.append(d)
            
            return unique_detections
        except Exception as e:
            print(f"HTML analysis warning: {str(e)}")
            return []

    async def _perform_ssl_analysis(self, hostname: str) -> Dict[str, Any]:
        try:
            return await self.ssl_detector.detect_waf_by_ssl(hostname)
        except Exception as e:
            return {
                'ssl_analysis': {'valid': False, 'error': str(e)},
                'waf_detected': False
            }

    async def detect_waf(self, url: str) -> Dict[str, Any]:
        try:
            hostname = url.split('//')[-1].split('/')[0].split(':')[0]
            self.mensagem_strategy.mostrar_progresso("Checking connection")            
            ssl_results = await self._perform_ssl_analysis(hostname)
            
            async with RequestHandler() as handler:
                self.mensagem_strategy.mostrar_progresso("  Analyzing response")
                response, analysis_type = await handler.get(url)
                self.mensagem_strategy.mostrar_progresso("   Finalizing analysis")
                waf_info = await self.detection_strategy.check_waf(response, self.waf_db)
                html_detections = await self._process_html_detections(url, handler)
                
                
                
                self.results.update({
                    'target': url,
                    'waf_detected': waf_info['detected'] or ssl_results.get('waf_detected', False),
                    'waf_name': waf_info['name'] or ssl_results.get('waf_name'),
                    'confidence': max(waf_info['confidence'], ssl_results.get('confidence', 0)),
                    'evidence': " | ".join(filter(None, [
                        waf_info['evidence'],
                        ssl_results.get('evidence')
                    ])),
                    'blocked': waf_info['blocked'],
                    'status_code': waf_info['status_code'],
                    'timestamp': datetime.now().isoformat(),
                    'html_waf_detections': html_detections,
                    'ssl_analysis': ssl_results.get('ssl_analysis'),
                    'ssl_waf_detection': {
                        'detected': ssl_results.get('waf_detected', False),
                        'waf_name': ssl_results.get('waf_name'),
                        'confidence': ssl_results.get('confidence', 0),
                        'evidence': ssl_results.get('evidence')
                    },
                    'protocol_analysis': {
                        'http_version': getattr(response, 'http_version', '1.1'),
                        'http2_detected': waf_info.get('http2_detected', False),
                        'http2_evidence': waf_info.get('http2_evidence'),
                        'http2_confidence': waf_info.get('http2_confidence', 0)
                    }
                })
                
                return self.results
                
        except RequestError as e:
            raise Exception(f"Request failed: {str(e)}")
        except Exception as e:
            raise Exception(f"Analysis failed: {str(e)}")

    def get_results(self) -> Dict[str, Any]:
        return self.results
