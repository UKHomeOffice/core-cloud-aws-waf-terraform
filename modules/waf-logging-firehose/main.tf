locals {
  common_tags = merge(var.tags, {
    "waf:component" = "logging"
    "waf:env"       = var.environment
  })

  destination_bucket_name = replace(var.destination_s3_bucket_arn, "arn:aws:s3:::", "")

  effective_stream_name_prefix = (
    startswith(var.stream_name_prefix, "aws-waf-logs-")
    ? var.stream_name_prefix
    : "aws-waf-logs-${var.stream_name_prefix}"
  )
}

resource "aws_iam_role" "firehose" {
  name = "${var.name_prefix}-${var.environment}-waf-firehose-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "firehoseAssume"
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "firehose" {
  name              = "/aws/kinesisfirehose/${var.name_prefix}-${var.environment}-waf"
  retention_in_days = var.firehose_error_log_retention_days
  kms_key_id        = var.cloudwatch_kms_key_arn
  tags              = local.common_tags
}

resource "aws_cloudwatch_log_stream" "firehose" {
  name           = "shared"
  log_group_name = aws_cloudwatch_log_group.firehose.name
}

data "aws_iam_policy_document" "firehose" {
  statement {
    sid    = "S3Delivery"
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject",
      "s3:PutObjectTagging"
    ]
    resources = [
      var.destination_s3_bucket_arn,
      "${var.destination_s3_bucket_arn}/*"
    ]
  }

  dynamic "statement" {
    for_each = var.enable_put_object_acl ? [1] : []
    content {
      sid     = "S3PutObjectAcl"
      effect  = "Allow"
      actions = ["s3:PutObjectAcl"]
      resources = ["${var.destination_s3_bucket_arn}/*"]
    }
  }

  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = ["logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.firehose.arn}:*"]
  }

  dynamic "statement" {
    for_each = var.s3_kms_key_arn != null ? [1] : []
    content {
      sid    = "KmsForS3"
      effect = "Allow"
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:DescribeKey"
      ]
      resources = [var.s3_kms_key_arn]
    }
  }
}

resource "aws_iam_role_policy" "firehose" {
  name   = "${var.name_prefix}-${var.environment}-waf-firehose-policy"
  role   = aws_iam_role.firehose.id
  policy = data.aws_iam_policy_document.firehose.json
}

data "aws_iam_policy_document" "bucket_policy" {
  count = var.manage_s3_bucket_policy ? 1 : 0

  statement {
    sid    = "AllowFirehoseWrite"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.firehose.arn]
    }

    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject"
    ]

    resources = [
      var.destination_s3_bucket_arn,
      "${var.destination_s3_bucket_arn}/*"
    ]
  }

  dynamic "statement" {
    for_each = var.enable_put_object_acl ? [1] : []
    content {
      sid    = "AllowFirehosePutObjectAcl"
      effect = "Allow"

      principals {
        type        = "AWS"
        identifiers = [aws_iam_role.firehose.arn]
      }

      actions = ["s3:PutObjectAcl"]

      resources = ["${var.destination_s3_bucket_arn}/*"]
    }
  }
}

resource "aws_s3_bucket_policy" "destination" {
  count  = var.manage_s3_bucket_policy ? 1 : 0
  bucket = local.destination_bucket_name
  policy = data.aws_iam_policy_document.bucket_policy[0].json
}

resource "aws_kinesis_firehose_delivery_stream" "this" {
  name        = "${local.effective_stream_name_prefix}${var.name_prefix}-${var.environment}${var.stream_name_suffix}"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = var.destination_s3_bucket_arn

    prefix = "waf/AWSLogs/!{partitionKeyFromQuery:account_id}/waf/!{partitionKeyFromQuery:region}/!{partitionKeyFromQuery:webacl}/!{partitionKeyFromQuery:year}/!{partitionKeyFromQuery:month}/!{partitionKeyFromQuery:day}/!{partitionKeyFromQuery:hour}/"

    error_output_prefix = "${trim(var.s3_error_output_prefix, "/")}/!{firehose:error-output-type}/"

    buffering_size     = var.buffer_size_mb
    buffering_interval = var.buffer_interval_seconds
    compression_format = var.compression_format

    kms_key_arn = var.s3_kms_key_arn

    dynamic_partitioning_configuration {
      enabled = true
    }

    processing_configuration {
      enabled = true

      processors {
        type = "MetadataExtraction"

        parameters {
          parameter_name  = "JsonParsingEngine"
          parameter_value = "JQ-1.6"
        }

        parameters {
          parameter_name  = "MetadataExtractionQuery"
          parameter_value = "{account_id:(.webaclId|split(\":\")|.[4]),region:(.webaclId|split(\":\")|.[3]),webacl:(.webaclId|capture(\"/webacl/(?<name>[^/]+)/\").name),year:(.timestamp/1000|floor|strftime(\"%Y\")),month:(.timestamp/1000|floor|strftime(\"%m\")),day:(.timestamp/1000|floor|strftime(\"%d\")),hour:(.timestamp/1000|floor|strftime(\"%H\"))}"
        }
      }
    }

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose.name
      log_stream_name = aws_cloudwatch_log_stream.firehose.name
    }
  }

  tags = local.common_tags
}