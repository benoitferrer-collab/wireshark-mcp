import sys
import os
import json
sys.path.insert(0, os.path.abspath("."))
from app.services.enrichment_service import get_threat_intel_service

def main():
    svc = get_threat_intel_service()
    print("CrowdSec Key present:", bool(getattr(svc, "crowdsec_key", None)))
    print("Testing IPs...")
    res = svc.get_threat_intel_summary(ips=["185.156.73.19", "8.8.8.8"])
    try:
        print(json.dumps(res, indent=2))
    except TypeError:
        print(res)


if __name__ == "__main__":
    main()
