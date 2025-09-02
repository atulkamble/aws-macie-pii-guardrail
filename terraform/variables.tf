variable "region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for all resources"
}

variable "project" {
  type        = string
  default     = "macie-pii-guardrail"
  description = "Project name used for resource naming"
}

variable "email" {
  type        = string
  description = "atul_kamble@hotmail.com"
}

