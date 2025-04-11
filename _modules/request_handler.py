#!/usr/bin/env python3
"""
myodReaktor :: solid responsibility principle
"""

import aiohttp
import random
from typing import Optional, Dict, Any, Tuple
from _modules.compatibility import FullResponseWrapper

class RequestHandler:
    DEFAULT_TIMEOUT = 30

    def __init__(self, headers: Optional[Dict[str, str]] = None, timeout: int = DEFAULT_TIMEOUT):
        self.headers = headers or self.get_default_headers()
        self.delay_range = (2, 5)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session = None

    @staticmethod
    def get_default_headers() -> Dict[str, str]:
        return {
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15'
            ]),
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.google.com/'
        }

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False))
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def get(self, url: str, **kwargs) -> Tuple[FullResponseWrapper, str]:
        if not self.session:
            raise RuntimeError("Session not started. Use async with.")
            
        try:
            response = await self.session.get(url, **kwargs)
            content_type = response.headers.get('Content-Type', '').lower()
            analysis_type = 'html' if 'text/html' in content_type else 'headers'
            return FullResponseWrapper(response), analysis_type
            
        except aiohttp.ClientError as e:
            raise RequestError(f"HTTP request failed: {str(e)}")

    async def post(self, url: str, data: Optional[Any] = None, **kwargs) -> Tuple[FullResponseWrapper, str]:
        if not self.session:
            raise RuntimeError("Session not started. Use async with.")
            
        try:
            response = await self.session.post(url, data=data, **kwargs)
            content_type = response.headers.get('Content-Type', '').lower()
            analysis_type = 'html' if 'text/html' in content_type else 'headers'
            return FullResponseWrapper(response), analysis_type
            
        except aiohttp.ClientError as e:
            raise RequestError(f"HTTP request failed: {str(e)}")

class RequestError(Exception):
    pass
