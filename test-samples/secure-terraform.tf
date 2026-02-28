# =============================================================================
# X-CloudSentinel Test Sample: SECURE Terraform Configuration
# This file demonstrates properly secured cloud infrastructure
# =============================================================================

provider "aws" {
  region = "us-east-1"
  # Using IAM roles or environment variables for authentication
  # No hardcoded credentials
}

# S3 Bucket - Properly secured
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-data-bucket"

  tags = {
    Name        = "Secure Bucket"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# S3 Bucket Server-Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# S3 Public Access Block - All enabled
resource "aws_s3_bucket_public_access_block" "secure_access" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

# Security Group - Properly restricted
resource "aws_security_group" "restricted_sg" {
  name        = "restricted_access"
  description = "Properly restricted security group"

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RDS Instance - Encrypted and private
resource "aws_db_instance" "secure_db" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  db_name              = "securedb"
  username             = var.db_username
  password             = var.db_password
  publicly_accessible  = false
  storage_encrypted    = true
  kms_key_id           = var.kms_key_id
  skip_final_snapshot  = false

  vpc_security_group_ids = [aws_security_group.restricted_sg.id]
}

# Variables - no hardcoded values
variable "db_username" {
  type        = string
  description = "Database administrator username"
  sensitive   = true
}

variable "db_password" {
  type        = string
  description = "Database administrator password"
  sensitive   = true
}

variable "kms_key_id" {
  type        = string
  description = "KMS key ID for encryption"
}

# CloudTrail - Properly enabled
resource "aws_cloudtrail" "enabled_trail" {
  name                          = "secure-trail"
  s3_bucket_name                = aws_s3_bucket.secure_bucket.id
  enable_logging                = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}

