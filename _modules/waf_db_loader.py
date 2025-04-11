# _modules/waf_db_loader.py

import os
import json
from typing import Dict, Any

def load_waf_db() -> Dict[str, Any]:
    """Carrega o banco de dados de WAFs a partir de um arquivo JSON."""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        waf_db_path = os.path.join(script_dir, "", "waf_technologies.json")
        with open(waf_db_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        raise Exception(f"Failed to load WAF database: {e}")
