import json
import random
import os

def generate_synthetic_data(output_path="f:/Fullbright Scholarship/X-CloudSentinel/backend/data/training_data.json"):
    data = []
    
    # --- TEMPLATES ---
    
    # SECURE Snippets
    templates_secure = [
        "resource \"aws_s3_bucket\" \"secure\" {\n  bucket = \"my-data\"\n  acl = \"private\"\n}",
        "resource \"aws_db_instance\" \"db\" {\n  storage_encrypted = true\n  publicly_accessible = false\n}",
        "FROM node:18-alpine\nUSER node\nCOPY . /app",
        "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: false",
        "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"s3:GetObject\",\n      \"Resource\": \"arn:aws:s3:::mybucket/*\"\n    }\n  ]\n}"
    ]
    
    # MISCONFIGURED Snippets
    templates_misconfigured = [
        "resource \"aws_s3_bucket\" \"insecure\" {\n  bucket = \"my-data\"\n  acl = \"public-read\"\n}",
        "resource \"aws_db_instance\" \"db\" {\n  storage_encrypted = false\n  publicly_accessible = true\n}",
        "FROM node:latest\nUSER root\nADD . /app",
        "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: true",
        "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"*\",\n      \"Resource\": \"*\"\n    }\n  ]\n}"
    ]
    
    # SECRET LEAKAGE Snippets
    templates_secrets = [
        "aws_access_key = \"AKIA1234567890ABCDEF\"",
        "aws_secret_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
        "export GITHUB_TOKEN=\"ghp_1234567890abcdefghijklmnopqrstuv\"",
        "connection_string = \"postgres://admin:password123@db.example.com:5432\"",
        "\"password\": \"SuP3rS3cr3t!\""
    ]
    
    # HIGH RISK Snippets (Combine Misconfig + Secrets)
    templates_high_risk = [
        "resource \"aws_s3_bucket\" \"risk\" {\n  bucket = \"data\"\n  access_key = \"AKIA123...\"\n  acl = \"public-read\"\n}",
        "FROM ubuntu\nENV PASSWORD=root\nRUN apt-get update && apt-get install sudo",
        "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n  - name: root\n    env:\n    - name: SECRET\n      value: \"123456\"\n    securityContext:\n      privileged: true"
    ]
    
    categories = [
        ('Secure', templates_secure),
        ('Misconfigured', templates_misconfigured),
        ('SecretLeakage', templates_secrets),
        ('HighRisk', templates_high_risk)
    ]
    
    # Generate balanced dataset
    for i in range(250): # 250 per class = 1000 total for MVP
        for label, templates in categories:
            snippet = random.choice(templates)
            # Add some slight variation/noise
            if random.random() > 0.5:
                snippet += f" # Comment {random.randint(1, 1000)}"
            
            data.append({
                "text": snippet,
                "label": label
            })
            
    random.shuffle(data)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Generated {len(data)} synthetic samples at {output_path}")

if __name__ == "__main__":
    generate_synthetic_data()

