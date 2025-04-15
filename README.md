
**myodReaktor** é um detector WAFs (Web Application Firewalls) qua aplica técnica de fingerprinting  análise probabilística  multifatorial,combinando verificação de header HTTP e HTTP/2, SSL incluindo análise de DOM e status de bloqueio.


**saida da checkagem:**            
```
python myodReaktor.py -u https://xXx.com/id=11

 _____ _   _  ___   ___   ___   ___  ____ _   _ _____ ____  ______
 | | |  \_/  |   | |   \ |___/ |___ |___| |__/    |   |   | |____/
 | | |   |   |___| |___/ |   \_|___ |   | |  \_   |   |___| |    \_
 myodReaktor.py <url>                        :::WAF Detector Stealth



   ---------------        ---------------        ---------------     
   ---------------        ---------------        ---------------     
   ---------------        ---------------        ---------------     
   ---------------        ---------------        ---------------     
   ---------------        ---------------        ---------------     
   ---------------        ---------------        ---------------     
   ---------------        ---------------        ---------------     
   ---------------        ---------------        ---------------     
   ---------------        ---------------        ---------------     
   ---------------        ---------------        ---------------     
Checking connection |  Analyzing response |    Finalizing analysis

::: ============================================================ :::

{
  "target": "https://xXx.com/id=11",
  "timestamp": "2025-04-13T16:10:51.874664",
  "html_analysis": {
    "detected_wafs": [
      {
        "waf": "Sucuri Firewall",
        "company": "Sucuri",
        "evidence": "Regex: sucuri|cloudproxy|sucuri\\/cloudproxy"
      },
      {
        "waf": "GoDaddy WAF",
        "company": "GoDaddy",
        "evidence": "Regex: godaddy|secureserver\\.net|wpaas"
      }
    ]
  },
  "stealth_analysis": {
    "waf_detected": true,
    "waf_name": "Sucuri Firewall",
    "confidence": 0.8999999999999999,
    "evidence": "Header 'server' + Header 'x-sucuri-id' + Header 'x-sucuri-cache' | SSL Certificate match: Inc.",
    "blocked": false,
    "status_code": 200,
    "timestamp": "2025-04-13T16:10:51.874126",
    "protocol_analysis": {
      "http_version": "1.1",
      "http2_detected": false,
      "http2_evidence": null,
      "http2_confidence": 0
    }
  },
  "ssl_analysis": {
    "valid": true,
    "issuer": "GoDaddy.com, Inc.",
    "subject": "xXx.com.lb",
    "expiration": "xxxxxxxx",
    "issued": "x-x-x-x-x",
    "serial_number": "x-x-x-x-x",
    "signature_algorithm": "sha256WithRSAEncryption",
    "version": 2,
    "fingerprint": "x3:x3:x4:x4:x13",
    "protocol": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384"
  }
}


```
