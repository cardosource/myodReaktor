#!/usr/bin/env python3
import ssl
import socket
import asyncio
from typing import Dict, Any
from datetime import datetime
from OpenSSL import crypto
from ssl import SSLError

class SSLAnalyzer:
    async def analyze_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ip = socket.gethostbyname(hostname)
            conn = socket.create_connection((ip, port), timeout=5)
            sock = context.wrap_socket(conn, server_hostname=hostname)
            
            try:
                cert_der = sock.getpeercert(binary_form=True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
                
                def get_components(name):
                    return {k.decode(): v.decode() for k, v in name.get_components()} if name else {}
                
                issuer = get_components(cert.get_issuer())
                subject = get_components(cert.get_subject())
                
                return {
                    'valid': True,
                    'issuer': issuer.get('O', 'Unknown'),
                    'subject': subject.get('CN', hostname),
                    'expiration': cert.get_notAfter().decode('ascii'),
                    'issued': cert.get_notBefore().decode('ascii'),
                    'serial_number': str(cert.get_serial_number()),
                    'signature_algorithm': cert.get_signature_algorithm().decode('utf-8'),
                    'version': cert.get_version(),
                    'fingerprint': cert.digest('sha1').decode('utf-8'),
                    'protocol': sock.version(),
                    'cipher': sock.cipher()[0] if sock.cipher() else None
                }
            finally:
                sock.close()
                conn.close()

        except ssl.SSLError as e:
            if "UNEXPECTED_EOF_WHILE_READING" in str(e):
                return {
                    'valid': False,
                    'error': 'SSL handshake failed: unexpected EOF',
                    'error_type': 'SSLUnexpectedEOF'
                }
            return {
                'valid': False,
                'error': str(e),
                'error_type': f"SSLError ({e.__class__.__name__})"
            }
        except socket.timeout:
            return {
                'valid': False,
                'error': 'Connection timed out',
                'error_type': 'TimeoutError'
            }
        except Exception as e:
            return {
                'valid': False,
                'error': str(e),
                'error_type': type(e).__name__
            }

class PassiveSSLDetection:
    
    def __init__(self, waf_db: Dict[str, Any]):
        self.waf_db = waf_db
        self.analyzer = SSLAnalyzer()
    
    async def detect_waf_by_ssl(self, hostname: str) -> Dict[str, Any]:
        try:
            cert_info = await self.analyzer.analyze_certificate(hostname)
            
            if not cert_info.get('valid', False):
                return {
                    'ssl_analysis': cert_info,
                    'waf_detected': False
                }
            
            for waf_id, waf_data in self.waf_db.get('wafs', {}).items():
                ssl_patterns = waf_data.get('ssl_patterns', [])
                for pattern in ssl_patterns:
                    if (isinstance(pattern, str) and 
                        (pattern.lower() in cert_info['issuer'].lower() or 
                         pattern.lower() in cert_info['subject'].lower())):
                        return {
                            'ssl_analysis': cert_info,
                            'waf_detected': True,
                            'waf_name': waf_data['name'],
                            'confidence': 0.85,
                            'evidence': f"SSL Certificate match: {pattern}",
                            'blocked': False,
                            'status_code': None
                        }
            
            return {
                'ssl_analysis': cert_info,
                'waf_detected': False
            }
        except Exception as e:
            return {
                'ssl_analysis': {
                    'valid': False,
                    'error': str(e),
                    'error_type': type(e).__name__
                },
                'waf_detected': False
            }
