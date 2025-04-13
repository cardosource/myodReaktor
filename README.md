
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
  "target": "https://xxx.com",
  "timestamp": "2025-04-08T07:38:16.187532",
  "header_analysis": {
    "target": "https://xxx.com",
    "waf_detected": true,
    "waf_name": "Sucuri Firewall",
    "confidence": 0.9,
    "evidence": "Header 'server' + Header 'x-sucuri-id' + Header 'x-sucuri-cache'",
    "blocked": false,
    "status_code": 200,
    "timestamp": "2025-04-08T07:38:14.949517"
  },
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
  }
}

```
