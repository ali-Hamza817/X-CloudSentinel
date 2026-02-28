import re
import socket

class SentinelNetworkScanner:
    """
    Scans code for malicious URLs and vulnerable port configurations.
    Designed for the research-grade network security layer.
    """
    def __init__(self):
        # Vulnerable ports that should almost never be exposed to 0.0.0.0
        self.vulnerable_ports = {
            27017: "MongoDB (Commonly targeted for ransomware)",
            3306: "MySQL/MariaDB",
            5432: "PostgreSQL",
            6379: "Redis (No auth by default)",
            9200: "Elasticsearch",
            22: "SSH",
            23: "Telnet (Insecure)",
            1433: "MSSQL"
        }
        
        # Mock reputation list for malicious/suspicious domains
        self.suspicious_domains = [
            "malicious-cluster-check.com",
            "proxy-attack.io",
            "miner-pool.xyz",
            "attack-vector.net"
        ]

    def scan(self, text):
        results = {
            "vulnerable_ports": [],
            "suspicious_urls": [],
            "exposure_risks": []
        }

        # 1. Regex for Port detection in connection strings (e.g., :27017)
        port_matches = re.findall(r':(\d{2,5})', text)
        for p in port_matches:
            port_num = int(p)
            if port_num in self.vulnerable_ports:
                results["vulnerable_ports"].append({
                    "port": port_num,
                    "service": self.vulnerable_ports[port_num],
                    "risk": "High"
                })

        # 2. Regex for URLs
        url_matches = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        for url in url_matches:
            for domain in self.suspicious_domains:
                if domain in url:
                    results["suspicious_urls"].append({
                        "url": url,
                        "risk": "Critical",
                        "reason": f"Matches known suspicious domain: {domain}"
                    })

        # 3. Detect 0.0.0.0 / 0.0.0.0/0 exposure in IaC
        if "0.0.0.0" in text or "0.0.0.0/0" in text or "cidr_blocks = [\"0.0.0.0/0\"]" in text:
            results["exposure_risks"].append({
                "type": "Wildcard Exposure",
                "risk": "High",
                "description": "Resource exposed to the entire internet (0.0.0.0/0). Combined with database ports, this is a Critical risk."
            })

        return results

if __name__ == "__main__":
    scanner = SentinelNetworkScanner()
    test_text = 'mongodb://user:pass@attack-vector.net:27017'
    print(scanner.scan(test_text))
