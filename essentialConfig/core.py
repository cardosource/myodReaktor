#!/usr/bin/env python3
"""
myodReaktor :: solide close open dependence inject

"""

import json
from datetime import datetime
from typing import List, Dict, Any
from _modules.request_handler import RequestHandler, RequestError
from _modules.mensagem import ProgressoVertical
from _modules.waf_db_loader import load_waf_db


class WAFDetector:
    def __init__(self, waf_db: Dict[str, Any] = None,
                 detection_strategy: Any = None,
                 mensagem_strategy: Any = None,
                 scanner_strategy: Any = None):
        self.waf_db = waf_db or load_waf_db()
        self._initialize_results()
        self.detection_strategy = detection_strategy
        self.mensagem_strategy = mensagem_strategy or ProgressoVertical()
        self.scanner_strategy = scanner_strategy

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
            'html_waf_detections': []
        }

    async def _fetch_html_content(self, url: str, handler: RequestHandler) -> str:
        try:
            response, _ = await handler.get(url)
            return await response.text()
        except RequestError as e:
            raise Exception(f"Failed to fetch HTML content: {str(e)}")

    async def _process_html_detections(self, url: str, handler: RequestHandler) -> List[Dict[str, Any]]:
        if not self.scanner_strategy:
            raise Exception("Scanner strategy is not set")

        html_scanner = self.scanner_strategy
        detected_wafs = []

        for test_url in html_scanner.generate_test_urls(url):
            try:
                content = await self._fetch_html_content(test_url, handler)
                detections = await html_scanner.scan(content)
                for detection in detections:
                    if not any(d['waf'] == detection['waf'] for d in detected_wafs):
                        detected_wafs.append(detection)
            except Exception:
                continue

        return detected_wafs

    async def detect_waf(self, url: str) -> Dict[str, Any]:
        try:
            self.mensagem_strategy.mostrar_progresso("Checking connection")

            async with RequestHandler() as handler:
                response, _ = await handler.get(url)

                self.mensagem_strategy.mostrar_progresso(" Analyzing response")

                waf_info = await self.detection_strategy.check_waf(response, self.waf_db)

                self.mensagem_strategy.mostrar_progresso("   Finalizing analysis")

                html_detections = await self._process_html_detections(url, handler)

                self.results.update({
                    'target': url,
                    'waf_detected': waf_info['detected'],
                    'waf_name': waf_info['name'],
                    'confidence': round(waf_info['confidence'], 2),
                    'evidence': waf_info['evidence'],
                    'blocked': waf_info['blocked'],
	            'status_code': waf_info['status_code'],
                    'timestamp': datetime.now().isoformat(),
                    'html_waf_detections': html_detections
                })

                return self.results

        except RequestError as e:
            raise Exception(f"Request failed: {str(e)}")
        except Exception as e:
            raise Exception(f"Analysis failed: {str(e)}")

    def get_results(self) -> Dict[str, Any]:
        return self.results
