import argparse
import json
import sys
from tabulate import tabulate

def load_config(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file '{filepath}' not found.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON configuration: {e}", file=sys.stderr)
        sys.exit(1)

def audit_infrastructure(config):
    findings = []
    
    # 1. Check Security Groups for overly permissive rules (Port 22/3389 exposed to 0.0.0.0/0)
    for sg in config.get("security_groups", []):
        for rule in sg.get("ingress_rules", []):
            if rule.get("cidr_block") == "0.0.0.0/0" and rule.get("port") in [22, 3389]:
                findings.append({
                    "resource_type": "Security Group",
                    "resource_id": f"{sg.get('name')} ({sg.get('id')})",
                    "issue": f"Overly Permissive Port {rule.get('port')} Exposed to 0.0.0.0/0",
                    "severity": "HIGH",
                    "remediation": "Restrict CIDR block to specific trusted corporate IPs or use AWS Systems Manager Session Manager."
                })

    # 2. Check Storage Volumes for lack of encryption
    for vol in config.get("storage_volumes", []):
        if not vol.get("encrypted", True):
            findings.append({
                "resource_type": "EBS Volume",
                "resource_id": vol.get("volume_id"),
                "issue": "Unencrypted Storage Volume",
                "severity": "MEDIUM",
                "remediation": "Enable default EBS encryption or migrate data to a newly encrypted snapshot/volume."
            })

    # 3. Check Network Interfaces for unattached/orphaned ENIs
    for eni in config.get("network_interfaces", []):
        if eni.get("status") == "available":
            findings.append({
                "resource_type": "Network Interface (ENI)",
                "resource_id": eni.get("eni_id"),
                "issue": "Unattached (Orphaned) Network Interface",
                "severity": "LOW",
                "remediation": "Delete orphaned ENIs to eliminate clutter and potential security blind spots."
            })

    return findings

def main():
    parser = argparse.ArgumentParser(description="Cloud Architecture Best-Practice & Security Auditor")
    parser.add_argument("config", nargs="?", default="configs/infrastructure.json", help="Path to cloud infrastructure JSON configuration")
    parser.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH"], help="Filter findings by minimum severity")
    
    args = parser.parse_args()
    
    print("======================================================================")
    print("           AWS SUPPORT: CLOUD ARCHITECTURE SECURITY AUDITOR           ")
    print("======================================================================\n")
    print(f"Scanning configuration profile: {args.config}...\n")
    
    config = load_config(args.config)
    findings = audit_infrastructure(config)
    
    if not findings:
        print("✅ No architecture misfindings or security violations detected.")
        return

    table_data = []
    severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    
    for f in findings:
        if args.severity and severity_order.get(f["severity"], 0) < severity_order.get(args.severity, 0):
            continue
        table_data.append([
            f["resource_type"],
            f["resource_id"],
            f["issue"],
            f["severity"],
            f["remediation"]
        ])

    if not table_data:
        print("No findings match the specified severity filter.")
        return

    headers = ["Resource Type", "Resource ID / Name", "Security Finding", "Severity", "AWS Best-Practice Remediation"]
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
    print(f"\nTotal security & operational findings: {len(table_data)}")

if __name__ == "__main__":
    main()
