#!/usr/bin/env python3
"""
myodReaktor ::  WAF Detector - Responsabilidade Principal
"""

import aiohttp
import json
import os
from datetime import datetime
import progressbar
from time import sleep
from _modules.compatibility import FullResponseWrapper

class WAFDetector:
    BANNER = r"""
 _____ _   _  ___   ___   ___   ___  ____ _   _ _____ ____  ______
 | | |  \_/  |   | |   \ |___/ |___ |___| |__/    |   |   | |____/
 | | |   |   |___| |___/ |   \_|___ |   | |  \_   |   |___| |    \_
 myodReaktor.py <url>                                                                                                                                                                                                                       
"""
    print("\033[93m" + BANNER + "\033[0m")
    def __init__(self, waf_db=None, detection_strategy=None):
        self.waf_db = waf_db or self._load_waf_db()
        self.results = {
            'target': None,
            'waf_detected': False,
            'waf_name': None,
            'confidence': 0,
            'evidence': None,
            'blocked': False,
            'status_code': None,
            'timestamp': None
        }
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        self.detection_strategy = detection_strategy

    def _load_waf_db(self):
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            waf_db_path = os.path.join(script_dir, "waf_technologies.json")
            with open(waf_db_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise Exception(f"Failed to load WAF database: {e}")
    
    def _animate_progress(self, label, duration=1.0, steps=20):
        widgets = [
            f'   {label} [ ',
            progressbar.Bar(marker='#', left='  ', right='    '),
            ' ]',
            progressbar.Percentage()
        ]
        with progressbar.ProgressBar(widgets=widgets, max_value=100) as bar:
            for i in range(0, 79, 5):  
                bar.update(i)
                sleep(duration/steps)

    async def detect_waf(self, url):
        try:
            self._animate_progress("Checking connection")
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(url, ssl=False) as response:
                    self._animate_progress("Analyzing response")
                    
                    #wrapper LSP
                    wrapped_response = FullResponseWrapper(response)
                    waf_info = await self.detection_strategy.check_waf(wrapped_response, self.waf_db)
                    
                    self._animate_progress("Finalizing analysis")
                    
                    self.results = {
                        'target': url,
                        'waf_detected': waf_info['detected'],
                        'waf_name': waf_info['name'],
                        'confidence': round(waf_info['confidence'], 2),
                        'evidence': waf_info['evidence'],
                        'blocked': waf_info['blocked'],
                        'status_code': waf_info['status_code'],
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    return self.results
                    
        except Exception as e:
            raise Exception(f"Analysis failed: {str(e)}")

    def get_results(self):
        return self.results
