# AWS Resource Management Tools

A collection of scripts for managing AWS resources, automating provisioning and cleanup, and maintaining resource inventory.

**Authored by V Vier**

## Tools in this Category

### 1. `ec2_instance_manager.py`
Comprehensive EC2 instance management script for launching, stopping, starting, and terminating instances with various configuration options.

### 2. `s3_bucket_manager.py`
Create, configure, and manage S3 buckets with versioning, lifecycle policies, and access controls.

### 3. `resource_tagger.py`
Bulk tagging tool for AWS resources with support for tag inheritance, tag enforcement, and tag reporting.

### 4. `resource_inventory.py`
Generate comprehensive inventory reports of AWS resources across regions and accounts.

### 5. `cleanup_unused_resources.sh`
Identify and optionally remove unused or abandoned AWS resources to reduce costs and clutter.

### 6. `ami_lifecycle_manager.py`
Automate the creation, distribution, and cleanup of Amazon Machine Images (AMIs).

### 7. `ebs_snapshot_manager.py`
Manage EBS snapshots with automated creation, retention policies, and cleanup.

### 8. `cloudformation_deployer.py`
Streamline CloudFormation stack deployments with parameter management and stack update capabilities.

## Usage Examples

### EC2 Instance Manager

```bash
# Launch a new EC2 instance
python ec2_instance_manager.py launch --name "web-server" --type "t3.micro" --ami "ami-0c55b159cbfafe1f0" --key-name "my-key" --security-group "sg-12345"

# Stop running instances with specific tag
python ec2_instance_manager.py stop --tag "Environment=Development"

# Get status of all instances
python ec2_instance_manager.py status --all
```

### Resource Tagger

```bash
# Tag all EC2 instances with project information
python resource_tagger.py --resource-type ec2 --tag-key "Project" --tag-value "WebApp" --region "us-east-1"

# Apply multiple tags from a JSON file
python resource_tagger.py --resource-type s3 --tags-file "tags.json" --region "us-west-2"
```

### Cleanup Unused Resources

```bash
# Identify unused resources (dry run)
./cleanup_unused_resources.sh --dry-run

# Clean up unused EBS volumes
./cleanup_unused_resources.sh --resource-type ebs --older-than 30d

# Clean up unattached Elastic IPs
./cleanup_unused_resources.sh --resource-type eip
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
