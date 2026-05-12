terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.44.0"
    }
  }
}

resource "aws_s3_bucket" "hack_me" {
  bucket = "super-insecure-bucket"

  acl = "public-read-write"
}

resource "aws_s3_bucket_versioning" "this_is_bad" {
  bucket = aws_s3_bucket.hack_me.id
  versioning_configuration {
    status = "Disabled"
  }
}