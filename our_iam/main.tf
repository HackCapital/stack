variable account_id {}
variable metadata {}
resource "aws_iam_policy" "billing" {
  arn = "arn:aws:iam::aws:policy/job-function/Billing"
}

resource "aws_iam_policy" "cloudwatch_full" {
  arn = "arn:aws:iam::aws:policy/CloudWatchFullAccess"
}

resource "aws_iam_policy" "cloudwatch_read" {
  arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
}

resource "aws_iam_policy" "ec2_read" {
  arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

resource "aws_iam_policy" "ec2_full" {
  arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_iam_policy" "ec2_container_service_read" {
  arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_policy" "ec2_container_service_full" {
  arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerServiceFullAccess"
}

resource "aws_iam_policy" "vpc_read" {
  arn = "arn:aws:iam::aws:policy/AmazonVPCReadOnlyAccess"
}

resource "aws_iam_policy" "kinesis_read" {
  arn = "arn:aws:iam::aws:policy/AmazonKinesisReadOnlyAccess"
}

resource "aws_iam_policy" "kinesis_full" {
  arn = "arn:aws:iam::aws:policy/AmazonKinesisFullAccess"
}

resource "aws_iam_policy" "elasticache_read" {
  arn = "arn:aws:iam::aws:policy/AmazonElastiCacheReadOnlyAccess"
}

resource "aws_iam_policy" "elasticache_full" {
  arn = "arn:aws:iam::aws:policy/AmazonElastiCacheFullAccess"
}

resource "aws_iam_policy" "s3_read" {
  arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_policy" "s3_full" {
  arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_policy" "cloudtrail_read" {
  arn = "arn:aws:iam::aws:policy/AWSCloudTrailReadOnlyAccess"
}

resource "aws_iam_policy" "rds_read" {
  arn = "arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess"
}

resource "aws_iam_policy" "lambda_read" {
  arn = "arn:aws:iam::aws:policy/AWSLambdaReadOnlyAccess"
}

resource "aws_iam_policy" "lambda_full" {
  arn = "arn:aws:iam::aws:policy/AWSLambdaFullAccess"
}

resource "aws_iam_policy" "macie_full" {
  arn = "arn:aws:iam::aws:policy/AmazonMacieFullAccess"
}

resource "aws_iam_policy" "iam_read" {
  arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
}

resource "aws_iam_saml_provider" "okta" {
  name                   = "Okta"
  saml_metadata_document = "${file("../../metadata.xml")}"
}

resource "aws_iam_role" "billing-okta-sso-role" {
  name        = "billing-okta-sso-role"
  description = "Role that allows billing management without touching other infra."

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${var.account_id}:saml-provider/${aws_iam_saml_provider.okta.name}"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "billing-billingOktaSSO-attach" {
  role       = "${aws_iam_role.billing-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/job-function/Billing"
}

resource "aws_iam_role" "admin-okta-sso-role" {
  name        = "admin-okta-sso-role"
  description = "Allows full admin access to the infrastructure for a few select employees."

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${var.account_id}:saml-provider/${aws_iam_saml_provider.okta.name}"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "admin-adminOktaSSO-attach" {
  role       = "${aws_iam_role.admin-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role" "audit-okta-sso-role" {
  name        = "audit-okta-sso-role"
  description = "Allows read only access to resources that are important for auditing"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${var.account_id}:saml-provider/${aws_iam_saml_provider.okta.name}"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "audit-auditOktaSSO-ec2-attach" {
  role       = "${aws_iam_role.audit-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "audit-auditOktaSSO-s3-attach" {
  role       = "${aws_iam_role.audit-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "audit-auditOktaSSO-cloudtrail-attach" {
  role       = "${aws_iam_role.audit-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSCloudTrailReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "audit-auditOktaSSO-macie-attach" {
  role       = "${aws_iam_role.audit-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonMacieFullAccess"
}

resource "aws_iam_role_policy_attachment" "audit-auditOktaSSO-iam-attach" {
  role       = "${aws_iam_role.audit-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "audit-auditOktaSSO-rds-attach" {
  role       = "${aws_iam_role.audit-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "audit-auditOktaSSO-cloudwatch-attach" {
  role       = "${aws_iam_role.audit-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
}

resource "aws_iam_role" "cloudwatch-okta-sso-role" {
  name        = "cloudwatch-okta-sso-role"
  description = "Full Access to cloudwatch intended for developers"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${var.account_id}:saml-provider/${aws_iam_saml_provider.okta.name}"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "cloudwatch-cloudwatchOktaSSO-attach" {
  role       = "${aws_iam_role.cloudwatch-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchFullAccess"
}

resource "aws_iam_role" "developer-okta-sso-role" {
  name        = "developer-okta-sso-role"
  description = "Full READ Access to most aws resources for debugging and planning purposes"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${var.account_id}:saml-provider/${aws_iam_saml_provider.okta.name}"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "developer-developerOktaSSO-ec2repository-attach" {
  role       = "${aws_iam_role.developer-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "developer-developerOktaSSO-ec2-attach" {
  role       = "${aws_iam_role.developer-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "developer-developerOktaSSO-vpc-attach" {
  role       = "${aws_iam_role.developer-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonVPCReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "developer-developerOktaSSO-kinesis-attach" {
  role       = "${aws_iam_role.developer-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonKinesisReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "developer-developerOktaSSO-elasticache-attach" {
  role       = "${aws_iam_role.developer-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonElastiCacheReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "developer-developerOktaSSO-s3-attach" {
  role       = "${aws_iam_role.developer-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "developer-developerOktaSSO-rds-attach" {
  role       = "${aws_iam_role.developer-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "developer-developerOktaSSO-lambda-attach" {
  role       = "${aws_iam_role.developer-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "developer-developerOktaSSO-cloudwatch-attach" {
  role       = "${aws_iam_role.developer-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
}

resource "aws_iam_role" "deployer-okta-sso-role" {
  name        = "deployer-okta-sso-role"
  description = "Allows for ecs updates and access to common troubleshooting places"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${var.account_id}:saml-provider/${aws_iam_saml_provider.okta.name}"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "deployer-deployerOktaSSO-ec2container-attach" {
  role       = "${aws_iam_role.deployer-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerServiceFullAccess"
}

resource "aws_iam_role_policy_attachment" "deployer-deployerOktaSSO-ec2-attach" {
  role       = "${aws_iam_role.deployer-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "deployer-deployerOktaSSO-cloudwatch-attach" {
  role       = "${aws_iam_role.deployer-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "deployer-deployerOktaSSO-deployment-attach" {
  role       = "${aws_iam_role.deployer-okta-sso-role.name}"
  policy_arn = "arn:aws:iam::648518523462:policy/deployment"
}