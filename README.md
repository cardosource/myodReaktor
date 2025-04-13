
**myodReaktor** é um detector WAFs (Web Application Firewalls) qua aplica técnica de fingerprinting  análise probabilística  multifatorial,combinando verificação de headers HTTP e HTTP/2, análise de DOM, códigos de status.


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
  "target": " https://xXx.com/id=11",
  "timestamp": "2025-04-13T13:11:55.115955",
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
    "confidence": 0.9,
    "evidence": "Header 'server' + Header 'x-sucuri-id' + Header 'x-sucuri-cache'",
    "blocked": false,
    "status_code": 200,
    "timestamp": "2025-04-13T13:11:55.115489",
    "protocol_analysis": {
      "http_version": "1.1",
      "http2_detected": false,
      "http2_evidence": null,
      "http2_confidence": 0
    }
  }
}

```
