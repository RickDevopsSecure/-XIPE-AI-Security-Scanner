# ============================================================
#  XIPE — Infraestructura AWS (Terraform)
#  Inbest Cybersecurity
# ============================================================

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region"        { default = "us-east-1" }
variable "teams_webhook_url" { description = "Teams Incoming Webhook URL" }
variable "vpc_id"            { description = "VPC ID donde corre Wazuh" }
variable "subnet_id"         { description = "Subnet pública para Fargate" }
variable "ecr_image_uri"     { description = "URI de la imagen XIPE en ECR" }
variable "schedule_expression" { default = "rate(1 day)" }  # cada 24h

# ── S3 Bucket para resultados ─────────────────────────────────────────────────
resource "aws_s3_bucket" "xipe_results" {
  bucket = "inbest-xipe-results-${data.aws_caller_identity.current.account_id}"
  tags   = { tool = "xipe", managed_by = "inbest" }
}

resource "aws_s3_bucket_versioning" "xipe_results" {
  bucket = aws_s3_bucket.xipe_results.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "xipe_results" {
  bucket = aws_s3_bucket.xipe_results.id
  rule {
    id     = "archive-old-reports"
    status = "Enabled"
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}

# ── SSM Parameter Store para configs de engagements ──────────────────────────
resource "aws_ssm_parameter" "xipe_teams_webhook" {
  name  = "/xipe/teams_webhook_url"
  type  = "SecureString"
  value = var.teams_webhook_url
}

# ── IAM Role para ECS Task ────────────────────────────────────────────────────
resource "aws_iam_role" "xipe_task_role" {
  name = "xipe-ecs-task-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "xipe_task_policy" {
  name = "xipe-task-policy"
  role = aws_iam_role.xipe_task_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.xipe_results.arn,
          "${aws_s3_bucket.xipe_results.arn}/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:GetParameters"]
        Resource = "arn:aws:ssm:${var.aws_region}:*:parameter/xipe/*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "xipe_execution_role" {
  name = "xipe-ecs-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "xipe_execution_policy" {
  role       = aws_iam_role.xipe_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ── CloudWatch Log Group ──────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "xipe" {
  name              = "/ecs/xipe"
  retention_in_days = 30
}

# ── ECS Cluster ───────────────────────────────────────────────────────────────
resource "aws_ecs_cluster" "xipe" {
  name = "xipe-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# ── Security Group para Fargate ───────────────────────────────────────────────
resource "aws_security_group" "xipe_fargate" {
  name        = "xipe-fargate-sg"
  description = "XIPE Fargate outbound only"
  vpc_id      = var.vpc_id

  # Solo salida (XIPE hace requests hacia el target)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ── ECS Task Definition ───────────────────────────────────────────────────────
resource "aws_ecs_task_definition" "xipe" {
  family                   = "xipe"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "1024"
  memory                   = "2048"
  task_role_arn            = aws_iam_role.xipe_task_role.arn
  execution_role_arn       = aws_iam_role.xipe_execution_role.arn

  container_definitions = jsonencode([{
    name      = "xipe"
    image     = var.ecr_image_uri
    essential = true

    environment = [
      { name = "S3_BUCKET", value = aws_s3_bucket.xipe_results.bucket },
    ]

    secrets = [
      { name = "TEAMS_WEBHOOK_URL", valueFrom = aws_ssm_parameter.xipe_teams_webhook.arn }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.xipe.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "xipe"
      }
    }
  }])
}

# ── IAM Role para Lambda ──────────────────────────────────────────────────────
resource "aws_iam_role" "xipe_lambda_role" {
  name = "xipe-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "xipe_lambda_policy" {
  name = "xipe-lambda-policy"
  role = aws_iam_role.xipe_lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecs:RunTask", "iam:PassRole"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = "arn:aws:ssm:${var.aws_region}:*:parameter/xipe/*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      }
    ]
  })
}

# ── Lambda Function ───────────────────────────────────────────────────────────
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_trigger.py"
  output_path = "${path.module}/lambda_trigger.zip"
}

resource "aws_lambda_function" "xipe_trigger" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "xipe-trigger"
  role             = aws_iam_role.xipe_lambda_role.arn
  handler          = "lambda_trigger.handler"
  runtime          = "python3.11"
  timeout          = 30
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ECS_CLUSTER        = aws_ecs_cluster.xipe.name
      ECS_TASK_DEF       = aws_ecs_task_definition.xipe.family
      SUBNET_ID          = var.subnet_id
      SECURITY_GROUP_ID  = aws_security_group.xipe_fargate.id
      S3_BUCKET          = aws_s3_bucket.xipe_results.bucket
      TEAMS_WEBHOOK_URL  = var.teams_webhook_url
      SSM_CONFIG_PATH    = "/xipe/config/default"
    }
  }
}

# ── EventBridge Schedule ──────────────────────────────────────────────────────
resource "aws_cloudwatch_event_rule" "xipe_schedule" {
  name                = "xipe-daily-scan"
  description         = "Dispara XIPE automáticamente según schedule"
  schedule_expression = var.schedule_expression  # "rate(1 day)" o "cron(0 8 * * ? *)"
}

resource "aws_cloudwatch_event_target" "xipe_lambda" {
  rule      = aws_cloudwatch_event_rule.xipe_schedule.name
  target_id = "xipe-lambda"
  arn       = aws_lambda_function.xipe_trigger.arn
  input = jsonencode({
    source = "aws.scheduler"
    note   = "Scheduled XIPE scan by Inbest"
  })
}

resource "aws_lambda_permission" "eventbridge_xipe" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xipe_trigger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.xipe_schedule.arn
}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "s3_bucket"       { value = aws_s3_bucket.xipe_results.bucket }
output "lambda_arn"      { value = aws_lambda_function.xipe_trigger.arn }
output "ecs_cluster"     { value = aws_ecs_cluster.xipe.name }
output "task_definition" { value = aws_ecs_task_definition.xipe.family }

data "aws_caller_identity" "current" {}
