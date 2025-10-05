# AWS Monitoring Tools

*Authored by V Vier*

A collection of Python and Bash scripts for monitoring AWS resources, creating dashboards, setting up alarms, and analyzing logs.

## Tools Overview

| Script | Description |
|--------|-------------|
| `cloudwatch_dashboard_creator.py` | Creates comprehensive CloudWatch dashboards for various AWS services |
| `metric_alarm_manager.py` | Manages CloudWatch alarms for different metrics and services |
| `log_analyzer.py` | Analyzes CloudWatch Logs for patterns, errors, and insights |
| `health_check_monitor.py` | Sets up health checks and monitoring for AWS resources |

## Installation

These scripts require the AWS CLI and Python 3.6+ with boto3 installed.

```bash
# Install dependencies
pip3 install boto3 tabulate colorama

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

### CloudWatch Dashboard Creator

Creates comprehensive CloudWatch dashboards for monitoring AWS resources.

```bash
# Create an EC2 dashboard
./cloudwatch_dashboard_creator.py --type ec2 --name my-ec2-dashboard

# Create an EC2 dashboard for specific instances
./cloudwatch_dashboard_creator.py --type ec2 --name my-ec2-dashboard --resources i-1234567890abcdef0 i-0987654321fedcba0

# Create an RDS dashboard
./cloudwatch_dashboard_creator.py --type rds --name my-rds-dashboard

# Create a Lambda dashboard
./cloudwatch_dashboard_creator.py --type lambda --name my-lambda-dashboard

# Create an ALB dashboard
./cloudwatch_dashboard_creator.py --type alb --name my-alb-dashboard

# Create a composite dashboard with key metrics from multiple services
./cloudwatch_dashboard_creator.py --type composite --name my-overview-dashboard

# List all dashboards
./cloudwatch_dashboard_creator.py --action list

# Delete a dashboard
./cloudwatch_dashboard_creator.py --action delete --name my-dashboard

# Use a specific region
./cloudwatch_dashboard_creator.py --type ec2 --name my-ec2-dashboard --region us-west-2

# Use a specific profile
./cloudwatch_dashboard_creator.py --type ec2 --name my-ec2-dashboard --profile production
```

### Metric Alarm Manager

Manages CloudWatch alarms for different metrics and services.

```bash
# Create CPU utilization alarm for EC2 instances
./metric_alarm_manager.py --create --type ec2-cpu --threshold 80 --period 300 --evaluation-periods 2 --comparison-operator GreaterThanThreshold

# Create disk space alarm for EC2 instances
./metric_alarm_manager.py --create --type ec2-disk --threshold 90 --period 300 --evaluation-periods 2 --comparison-operator GreaterThanThreshold

# Create memory usage alarm for EC2 instances (requires CloudWatch agent)
./metric_alarm_manager.py --create --type ec2-memory --threshold 80 --period 300 --evaluation-periods 2 --comparison-operator GreaterThanThreshold

# Create CPU utilization alarm for RDS instances
./metric_alarm_manager.py --create --type rds-cpu --threshold 80 --period 300 --evaluation-periods 2 --comparison-operator GreaterThanThreshold

# Create free storage space alarm for RDS instances
./metric_alarm_manager.py --create --type rds-storage --threshold 10 --period 300 --evaluation-periods 2 --comparison-operator LessThanThreshold

# Create error rate alarm for Lambda functions
./metric_alarm_manager.py --create --type lambda-errors --threshold 5 --period 300 --evaluation-periods 2 --comparison-operator GreaterThanThreshold

# List all alarms
./metric_alarm_manager.py --list

# Delete an alarm
./metric_alarm_manager.py --delete --name my-alarm
```

### Log Analyzer

Analyzes CloudWatch Logs for patterns, errors, and insights.

```bash
# Analyze logs for errors
./log_analyzer.py --group /aws/lambda/my-function --filter "ERROR" --start-time "2023-01-01T00:00:00" --end-time "2023-01-02T00:00:00"

# Analyze logs for a specific pattern
./log_analyzer.py --group /aws/lambda/my-function --filter "Exception" --start-time "-1h"

# Export logs to a file
./log_analyzer.py --group /aws/lambda/my-function --export logs.json --start-time "-1d"

# Generate a summary report
./log_analyzer.py --group /aws/lambda/my-function --report --start-time "-1d"
```

### Health Check Monitor

Sets up health checks and monitoring for AWS resources.

```bash
# Create a health check for a website
./health_check_monitor.py --create --type http --endpoint https://example.com --name my-website

# Create a health check for an EC2 instance
./health_check_monitor.py --create --type ec2 --resource i-1234567890abcdef0 --name my-instance

# Create a health check for an RDS instance
./health_check_monitor.py --create --type rds --resource my-database --name my-database

# List all health checks
./health_check_monitor.py --list

# Delete a health check
./health_check_monitor.py --delete --name my-health-check
```

## Examples

### Create a Dashboard for Production EC2 Instances

```bash
# Create a dashboard for production EC2 instances
./cloudwatch_dashboard_creator.py --type ec2 --name production-ec2-dashboard --resources i-1234567890abcdef0 i-0987654321fedcba0 --region us-west-2 --profile production
```

### Set Up CPU Alarms for All EC2 Instances

```bash
# Set up CPU alarms for all EC2 instances
./metric_alarm_manager.py --create --type ec2-cpu --threshold 80 --period 300 --evaluation-periods 2 --comparison-operator GreaterThanThreshold --region us-west-2 --profile production
```

### Analyze Lambda Function Errors

```bash
# Analyze Lambda function errors for the past day
./log_analyzer.py --group /aws/lambda/my-function --filter "ERROR" --start-time "-1d" --region us-west-2 --profile production
```

### Set Up Health Checks for Critical Services

```bash
# Set up health checks for critical services
./health_check_monitor.py --create --type http --endpoint https://api.example.com --name api-health-check --region us-west-2 --profile production
```

## Contributing

Feel free to contribute to this project by submitting pull requests or opening issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
