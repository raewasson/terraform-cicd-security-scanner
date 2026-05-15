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

resource "aws_iam_role" "example" {
  name = "example-role"
  assume_role_policy = data.aws_iam_policy_document.dummy_assume_role_policy.json
}

data "aws_iam_policy_document" "dummy_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "too_permissive" {
  statement {
    effect = "Allow"
    actions = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "too_permissive" {
  name = "too-permissive"
  role = aws_iam_role.example.id
  policy = data.aws_iam_policy_document.too_permissive.json
}

resource "aws_security_group" "wide_open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "example" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  disable_api_termination = false
}