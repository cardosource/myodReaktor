#!/usr/bin/env python3
"""
myodReaktor :: WAF Detection -  Liskov Substitution Principle
"""

from abc import ABC, abstractmethod

class ResponseWrapper(ABC):
    @property
    @abstractmethod
    def headers(self):
        pass
    
    @property
    @abstractmethod
    def status(self):
        pass
    
    @abstractmethod
    async def text(self):
        pass

class FullResponseWrapper(ResponseWrapper):
    def __init__(self, response):
        self._response = response
    
    @property
    def headers(self):
        return self._response.headers
    
    @property
    def status(self):
        return self._response.status
    
    async def text(self):
        return await self._response.text()

class HeadersOnlyWrapper(ResponseWrapper):    
    def __init__(self, response):
        self._response = response
    
    @property
    def headers(self):
        return self._response.headers
    
    @property
    def status(self):
        return self._response.status
    
    async def text(self):
        raise NoImplementedError

class FullResponseWithCookiesWrapper(FullResponseWrapper):    
    def __init__(self, response):
        super().__init__(response)
        self._cookies = response.cookies
    
    @property
    def cookies(self):
        return self._cookies
