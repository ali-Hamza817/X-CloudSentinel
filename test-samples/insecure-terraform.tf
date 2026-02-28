# =============================================================================
# X-CloudSentinel Test Sample: INSECURE Terraform Configuration
# This file contains INTENTIONAL security misconfigurations for testing
# DO NOT use in production!
# =============================================================================

# Provider with hardcoded credentials (SIQ-IAC-010 + SIQ-SEC-001, SIQ-SEC-002)
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# S3 Bucket - Public ACL, No Encryption (SIQ-IAC-002, SIQ-IAC-003)
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-insecure-data-bucket"
  acl    = "public-read"

  tags = {
    Name        = "Insecure Bucket"
    Environment = "production"
  }
}

# S3 Bucket Public Access Block - All disabled (SIQ-IAC-002)
resource "aws_s3_bucket_public_access_block" "vulnerable_access" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  restrict_public_buckets = false
  ignore_public_acls      = false
}

# Security Group - Open to the world (SIQ-IAC-004)
resource "aws_security_group" "wide_open_sg" {
  name        = "allow_everything"
  description = "Insecure security group"

  ingress {
    description = "Allow all inbound"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RDS Instance - Publicly accessible, unencrypted (SIQ-IAC-006, SIQ-IAC-007)
resource "aws_db_instance" "insecure_db" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  db_name              = "insecuredb"
  username             = "admin"
  password             = "SuperSecret123!Password"
  publicly_accessible  = true
  storage_encrypted    = false
  skip_final_snapshot  = true
}

# EBS Volume - Unencrypted (SIQ-IAC-008)
resource "aws_ebs_volume" "unencrypted_vol" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false

  tags = {
    Name = "unencrypted-volume"
  }
}

# CloudTrail - Logging disabled (SIQ-IAC-009)
resource "aws_cloudtrail" "disabled_trail" {
  name                          = "my-trail"
  s3_bucket_name                = aws_s3_bucket.vulnerable_bucket.id
  enable_logging                = false
  is_multi_region_trail         = false
}

# API Key hardcoded in a variable default (SIQ-SEC-007)
variable "api_config" {
  default = {
    api_key = "sk-1234567890abcdefghijklmnop"
    endpoint = "https://api.example.com"
  }
}

# Database URL with embedded credentials (SIQ-SEC-012)
variable "database_url" {
  default = "postgres://admin:MyDBP@ssw0rd@db.example.com:5432/production"
}

