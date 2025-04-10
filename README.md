
**myodReaktor** é um detector WAFs (Web Application Firewalls) usando técnica de fingerprinting  análise probabilística usando  detecção avançada  aplica princípios SOLID para análise multifatorial,combinando verificação de headers HTTP, análise de DOM, códigos de status.



```
   Checking connection [   ##########################################     ]100%
   Analyzing response [   ###########################################     ]100%
   Finalizing analysis [   ##########################################     ]100%

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
