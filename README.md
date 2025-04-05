
**myodReaktor** é um detector WAFs (Web Application Firewalls) usando múltiplas técnicas. 
Combina fingerprinting (analisando padrões em regex e headers), status HTTP e análise probabilística.



```
  Checking connection [   ##########################################     ]100%
   Analyzing response [   ###########################################     ]100%
   Finalizing analysis [   ##########################################     ]100%
{
  "target": "https://globalfoods.com.lb/product.php?id=229",
  "timestamp": "2025-04-05T03:40:39.780881",
  "header_analysis": {
    "target": "https://globalfoods.com.lb/product.php?id=229",
    "waf_detected": true,
    "waf_name": "Sucuri Firewall",
    "confidence": 0.9,
    "evidence": "Header 'server' + Header 'x-sucuri-id' + Header 'x-sucuri-cache'",
    "blocked": false,
    "status_code": 200,
    "timestamp": "2025-04-05T03:40:38.565962"
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
}```
