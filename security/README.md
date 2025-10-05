# AWS Security Tools

A collection of scripts for auditing, monitoring, and enhancing AWS security posture.

**Authored by V Vier**

## Tools in this Category

### 1. `iam_user_audit.py`
Comprehensive IAM user audit tool that identifies security risks such as users without MFA, inactive users, and users with overly permissive policies.

### 2. `security_group_analyzer.py`
Analyzes security groups to identify overly permissive rules, unused rules, and compliance violations.

### 3. `access_key_rotator.py`
Automates the rotation of IAM user access keys to maintain security best practices.

### 4. `public_resource_finder.py`
Identifies publicly accessible resources across your AWS account, including S3 buckets, RDS instances, and more.

### 5. `cloudtrail_analyzer.sh`
Analyzes CloudTrail logs to identify suspicious activities and potential security incidents.

### 6. `iam_role_analyzer.py`
Audits IAM roles to identify unused roles, overly permissive roles, and potential security risks.

### 7. `compliance_checker.py`
Checks AWS resources against common compliance frameworks such as CIS, HIPAA, and PCI DSS.

### 8. `encryption_validator.py`
Validates encryption settings across AWS services to ensure data is properly protected.

## Usage Examples

### IAM User Audit

```bash
# Perform a comprehensive IAM user audit
python iam_user_audit.py --full-report

# Find users with security issues
python iam_user_audit.py --find-issues

# Generate a compliance report
python iam_user_audit.py --compliance-report --output-format csv
```

### Security Group Analyzer

```bash
# Analyze all security groups in a region
python security_group_analyzer.py --region us-east-1

# Find overly permissive rules
python security_group_analyzer.py --check-permissive

# Check for compliance violations
python security_group_analyzer.py --compliance-check
```

### Access Key Rotator

```bash
# List access keys older than 90 days
python access_key_rotator.py --list-old-keys --days 90

# Rotate access keys for a specific user
python access_key_rotator.py --rotate --user-name john.doe

# Rotate all access keys older than 90 days
python access_key_rotator.py --rotate-all --days 90
```

### Public Resource Finder

```bash
# Find all publicly accessible resources
python public_resource_finder.py --all-resources

# Check only S3 buckets
python public_resource_finder.py --service s3

# Generate a detailed report
python public_resource_finder.py --detailed-report --output-format json
```

## Prerequisites

- Python 3.6+
- AWS CLI configured with appropriate permissions
- Boto3 library installed
- Bash shell (for shell scripts)

## Installation

```bash
pip install boto3 tabulate colorama
chmod +x *.sh
```
