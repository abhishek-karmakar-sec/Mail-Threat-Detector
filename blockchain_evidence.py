import hashlib
import json
import os
from datetime import datetime

LEDGER_FILE = "evidence_ledger.json"

def initialize_ledger():
    if not os.path.exists(LEDGER_FILE):
        with open(LEDGER_FILE, 'w') as f:
            json.dump([{"block": 0, "hash": "GENESIS_BLOCK_ATIK_007", "timestamp": str(datetime.now())}], f)

def store_blockchain_evidence(report_data):
    """Hashes the forensic report and cryptographically chains it to the previous block."""
    initialize_ledger()
    
    with open(LEDGER_FILE, 'r') as f:
        ledger = json.load(f)
        
    # Safely get the hash from the previous block
    previous_block = ledger[-1]
    previous_hash = previous_block.get('hash', 'UNKNOWN')
    
    # Create deterministic string from report data
    report_string = json.dumps(report_data, sort_keys=True)
    block_content = f"{previous_hash}{report_string}{datetime.now()}".encode()
    
    new_hash = hashlib.sha256(block_content).hexdigest()
    
    new_block = {
        "block": len(ledger),
        "timestamp": str(datetime.now()),
        "previous_hash": previous_hash,
        "hash": new_hash  # FIXED: Now consistently uses 'hash' instead of 'evidence_hash'
    }
    
    ledger.append(new_block)
    
    with open(LEDGER_FILE, 'w') as f:
        json.dump(ledger, f, indent=4)
        
    return new_hash