# AWS Cost Optimization Tools

*Authored by V Vier*

A collection of Python and Bash scripts for optimizing AWS costs, identifying savings opportunities, and implementing cost-effective resource management.

## Tools Overview

| Script | Description |
|--------|-------------|
| `resource_rightsizer.py` | Analyzes resource utilization and provides rightsizing recommendations |
| `reserved_instance_analyzer.py` | Analyzes EC2 usage patterns and recommends Reserved Instance purchases |
| `savings_plan_analyzer.py` | Analyzes compute usage and recommends Savings Plan purchases |
| `cost_anomaly_detector.py` | Detects unusual spending patterns and sends alerts |
| `idle_resource_finder.sh` | Identifies idle or unused resources that can be terminated |
| `cost_allocation_tagger.py` | Helps implement and enforce cost allocation tagging strategies |

## Installation

These scripts require the AWS CLI and Python 3.6+ with boto3 installed.

```bash
# Install dependencies
pip3 install boto3 tabulate colorama matplotlib pandas

# Make scripts executable
chmod +x *.py *.sh
```

## Configuration

The scripts use the AWS credentials and configuration from your environment. You can specify a profile or region when running the scripts.

```bash
# Configure AWS CLI if not already done
aws configure
```

## Usage

### Resource Rightsizer

Analyzes AWS resource utilization and provides recommendations for rightsizing to optimize costs while maintaining performance.

```bash
# Analyze all resources
./resource_rightsizer.py --service all

# Analyze EC2 instances
./resource_rightsizer.py --service ec2

# Analyze RDS instances
./resource_rightsizer.py --service rds

# Analyze DynamoDB tables
./resource_rightsizer.py --service dynamodb

# Analyze ElastiCache clusters
./resource_rightsizer.py --service elasticache

# Customize analysis parameters
./resource_rightsizer.py --days 30 --threshold 20

# Export results to JSON
./resource_rightsizer.py --export results.json --export-format json

# Export results to CSV
./resource_rightsizer.py --export results.csv --export-format csv

# Export results to HTML report
./resource_rightsizer.py --export report.html --export-format html

# Use a specific region
./resource_rightsizer.py --region us-west-2

# Use a specific profile
./resource_rightsizer.py --profile production
```

### Reserved Instance Analyzer

Analyzes EC2 usage patterns and recommends Reserved Instance purchases to optimize costs.

```bash
# Analyze all EC2 instances
./reserved_instance_analyzer.py

# Analyze specific instance types
./reserved_instance_analyzer.py --instance-types t3.medium m5.large

# Analyze instances with specific tags
./reserved_instance_analyzer.py --tags Environment=Production

# Customize analysis parameters
./reserved_instance_analyzer.py --lookback 90 --utilization 80

# Export results to CSV
./reserved_instance_analyzer.py --export ri_recommendations.csv
```

### Savings Plan Analyzer

Analyzes compute usage and recommends Savings Plan purchases to optimize costs.

```bash
# Analyze all compute usage
./savings_plan_analyzer.py

# Analyze specific services
./savings_plan_analyzer.py --services EC2 Fargate Lambda

# Customize analysis parameters
./savings_plan_analyzer.py --lookback 90 --commitment 80

# Export results to CSV
./savings_plan_analyzer.py --export sp_recommendations.csv
```

### Cost Anomaly Detector

Detects unusual spending patterns and sends alerts.

```bash
# Detect anomalies across all services
./cost_anomaly_detector.py

# Detect anomalies for specific services
./cost_anomaly_detector.py --services EC2 RDS S3

# Customize detection parameters
./cost_anomaly_detector.py --threshold 20 --lookback 30

# Send alerts to SNS topic
./cost_anomaly_detector.py --sns-topic arn:aws:sns:us-east-1:123456789012:CostAlerts

# Send alerts to email
./cost_anomaly_detector.py --email alerts@example.com
```

### Idle Resource Finder

Identifies idle or unused resources that can be terminated.

```bash
# Find all idle resources
./idle_resource_finder.sh

# Find idle resources of specific types
./idle_resource_finder.sh --resource-types ec2 ebs rds

# Customize idle thresholds
./idle_resource_finder.sh --cpu-threshold 5 --days 30

# Export results to CSV
./idle_resource_finder.sh --export idle_resources.csv
```

### Cost Allocation Tagger

Helps implement and enforce cost allocation tagging strategies.

```bash
# List resources missing required tags
./cost_allocation_tagger.py --list-untagged

# Define required tags
./cost_allocation_tagger.py --required-tags Environment Project Owner

# Apply default tags to untagged resources
./cost_allocation_tagger.py --apply-defaults Environment=Development Owner=Unknown

# Generate tagging compliance report
./cost_allocation_tagger.py --compliance-report --export tagging_compliance.csv
```

## Examples

### Comprehensive Cost Optimization Analysis

```bash
# Run a comprehensive cost optimization analysis
./resource_rightsizer.py --service all --days 30 --export rightsizing.html --export-format html
./reserved_instance_analyzer.py --lookback 90 --export ri.csv
./savings_plan_analyzer.py --lookback 90 --export sp.csv
./idle_resource_finder.sh --export idle.csv
./cost_allocation_tagger.py --compliance-report --export tagging.csv
```

### Scheduled Cost Optimization

```bash
# Create a cron job to run cost optimization analysis weekly
echo "0 0 * * 0 cd /path/to/scripts && ./resource_rightsizer.py --service all --export /path/to/reports/rightsizing_\$(date +\%Y\%m\%d).html --export-format html" | crontab -
```

### Automated Tagging Enforcement

```bash
# Create a cron job to enforce tagging policies daily
echo "0 1 * * * cd /path/to/scripts && ./cost_allocation_tagger.py --required-tags Environment Project Owner --apply-defaults Environment=Development Owner=Unknown" | crontab -
```

## Contributing

Feel free to contribute to this project by submitting pull requests or opening issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
