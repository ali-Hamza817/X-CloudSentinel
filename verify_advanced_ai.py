import requests
import json
import os

def test_advanced_analysis():
    url = "http://127.0.0.1:5000/analyze-advanced"
    
    # Test case 1: Insecure MongoDB Cluster with Secrets and Malicious URLs
    sample_code = """
    resource "aws_security_group" "db_sg" {
      name = "mongodb-cluster-sg"
      ingress {
        from_port   = 27017 # Vulnerable MongoDB Port
        to_port     = 27017
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"] # Wildcard Exposure
      }
    }

    resource "aws_db_instance" "malicious" {
      identifier = "cluster-attack-vector"
      endpoint   = "http://attack-vector.net:27017" # Malicious Domain + Port
      password   = "AKIA-SECRET-12345" # Contextual Secret (NER)
    }
    """
    
    # We'll save this temporarily to test GNN parsing
    temp_file = "f:/Fullbright Scholarship/X-CloudSentinel/test-samples/temp_research.tf"
    os.makedirs(os.path.dirname(temp_file), exist_ok=True)
    with open(temp_file, "w") as f:
        f.write(sample_code)

    payload = {
        "text": sample_code,
        "filePath": temp_file
    }

    print(f"Sending advanced analysis request for {temp_file}...")
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        result = response.json()
        
        print("\n--- Final Advanced Analysis Result ---")
        print(f"Overall Risk: {result['overall_risk']}")
        print(f"Baseline Prediction: {result['baseline']['prediction']}")
        
        print("\n[NER Secrets]")
        print(f"Count: {result['advanced']['secrets_ner']['count']}")
        print(f"Found: {result['advanced']['secrets_ner']['secrets']}")
        
        print("\n[GNN IaC Risk]")
        print(f"Prediction: {result['advanced']['gnn_iac']['prediction']}")
        print(f"Confidence: {result['advanced']['gnn_iac']['confidence']:.4f}")
        print(f"Nodes Analyzed: {result['advanced']['gnn_iac'].get('node_count')}")
        
        print("\n[Network Security Layer]")
        net = result['advanced']['network_security']
        print(f"Vulnerable Ports: {net['vulnerable_ports']}")
        print(f"Suspicious URLs: {net['suspicious_urls']}")
        print(f"Exposure Risks: {net['exposure_risks']}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)

if __name__ == "__main__":
    test_advanced_analysis()

