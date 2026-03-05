import asyncio
import json
import os
import sys

# Add backend to path
sys.path.append(os.getcwd())

from backend.services.ioc_extractor import ioc_extractor
from backend.services.stix_exporter import stix_exporter
from backend.services.threat_intel import threat_intel_service

async def test_sharing_workflow():
    print("--- Starting Threat Intelligence Sharing Workflow Test ---")
    
    # 1. Simulate a honeypot event with multiple IOCs
    mock_event = {
        "source_ip": "185.156.177.34",
        "raw_data": "Inbound connection from 185.156.177.34. SSH login attempt with username 'root'. Downloading malicious file from http://malicious-site.com/payload.exe. MD5: 44d88612fea8a8f36de82e1278abb02f",
        "honeypot_type": "SSH"
    }
    
    print(f"\n[1] Processing event from: {mock_event['source_ip']}")
    iocs = ioc_extractor.process_event(mock_event)
    print(f"Extracted {len(iocs)} IOCs:")
    for ioc in iocs:
        print(f"  - {ioc['type']}: {ioc['value']} ({ioc['threat_type']}, confidence: {ioc['confidence']})")
    
    # 2. Generate STIX 2.1 Bundle
    print("\n[2] Generating STIX 2.1 Bundle...")
    stix_bundle = stix_exporter.generate_bundle(iocs)
    if stix_bundle:
        print("STIX Bundle generated successfully (JSON length: ", len(stix_bundle), ")")
        # Save for manual inspection
        os.makedirs("reports", exist_ok=True)
        with open("reports/test_stix_bundle.json", "w") as f:
            f.write(stix_bundle)
        print("Saved to reports/test_stix_bundle.json")
    
    # 3. Test Daily Report Generation
    print("\n[3] Generating Daily Threat Report...")
    report_path = threat_intel_service.generate_daily_report(iocs, "reports/test_daily_feed.json")
    print(f"Daily report generated at: {report_path}")
    
    # 4. Simulate Platform Integration (these will be ignored if keys are missing, which is expected in test)
    print("\n[4] Simulating Platform Integration...")
    misp_res = await threat_intel_service.push_to_misp(iocs)
    print(f"MISP Push Result: {misp_res['status']} - {misp_res.get('message', 'N/A')}")
    
    otx_res = await threat_intel_service.push_to_otx(iocs)
    print(f"OTX Push Result: {otx_res['status']} - {otx_res.get('message', 'N/A')}")
    
    await threat_intel_service.close()
    print("\n--- Workflow Test Completed ---")

if __name__ == "__main__":
    asyncio.run(test_sharing_workflow())
