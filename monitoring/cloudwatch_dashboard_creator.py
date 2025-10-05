#!/usr/bin/env python3
"""
CloudWatch Dashboard Creator

This script creates comprehensive CloudWatch dashboards for monitoring AWS resources.
It can create dashboards for EC2 instances, RDS databases, Lambda functions, and more.

Author: V Vier
"""

import argparse
import boto3
import json
import sys
import time
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

class CloudWatchDashboardCreator:
    def __init__(self, region=None, profile=None):
        """Initialize the CloudWatch Dashboard Creator with optional region and profile."""
        session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
        self.cloudwatch = session.client('cloudwatch')
        self.ec2 = session.client('ec2')
        self.rds = session.client('rds')
        self.lambda_client = session.client('lambda')
        self.elb = session.client('elbv2')
        self.region = region or session.region_name
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        
    def create_ec2_dashboard(self, dashboard_name, instance_ids=None):
        """Create a CloudWatch dashboard for EC2 instances."""
        if not instance_ids:
            # Get all running instances if none specified
            response = self.ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            instance_ids = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_ids.append(instance['InstanceId'])
        
        if not instance_ids:
            print("No running EC2 instances found.")
            return False
            
        widgets = []
        
        # Add title widget
        widgets.append({
            "type": "text",
            "x": 0,
            "y": 0,
            "width": 24,
            "height": 1,
            "properties": {
                "markdown": "# EC2 Instances Dashboard\nCreated on " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        })
        
        # Add CPU utilization widget
        widgets.append({
            "type": "metric",
            "x": 0,
            "y": 1,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/EC2", "CPUUtilization", "InstanceId", instance_id ] for instance_id in instance_ids
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "CPU Utilization",
                "period": 300,
                "stat": "Average"
            }
        })
        
        # Add memory utilization widget (requires CloudWatch agent)
        widgets.append({
            "type": "metric",
            "x": 12,
            "y": 1,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "CWAgent", "mem_used_percent", "InstanceId", instance_id ] for instance_id in instance_ids
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Memory Utilization",
                "period": 300,
                "stat": "Average"
            }
        })
        
        # Add disk utilization widget (requires CloudWatch agent)
        widgets.append({
            "type": "metric",
            "x": 0,
            "y": 7,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "CWAgent", "disk_used_percent", "InstanceId", instance_id, "path", "/" ] for instance_id in instance_ids
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Disk Utilization (Root)",
                "period": 300,
                "stat": "Average"
            }
        })
        
        # Add network in/out widget
        widgets.append({
            "type": "metric",
            "x": 12,
            "y": 7,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/EC2", "NetworkIn", "InstanceId", instance_id ] for instance_id in instance_ids
                ] + [
                    [ "AWS/EC2", "NetworkOut", "InstanceId", instance_id ] for instance_id in instance_ids
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Network Traffic",
                "period": 300,
                "stat": "Average"
            }
        })
        
        # Add status check widget
        widgets.append({
            "type": "metric",
            "x": 0,
            "y": 13,
            "width": 24,
            "height": 3,
            "properties": {
                "metrics": [
                    [ "AWS/EC2", "StatusCheckFailed_System", "InstanceId", instance_id ] for instance_id in instance_ids
                ] + [
                    [ "AWS/EC2", "StatusCheckFailed_Instance", "InstanceId", instance_id ] for instance_id in instance_ids
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Status Checks",
                "period": 60,
                "stat": "Maximum"
            }
        })
        
        dashboard_body = {
            "widgets": widgets
        }
        
        try:
            self.cloudwatch.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=json.dumps(dashboard_body)
            )
            print(f"Successfully created EC2 dashboard: {dashboard_name}")
            return True
        except ClientError as e:
            print(f"Error creating dashboard: {e}")
            return False
    
    def create_rds_dashboard(self, dashboard_name, db_instances=None):
        """Create a CloudWatch dashboard for RDS instances."""
        if not db_instances:
            # Get all RDS instances if none specified
            response = self.rds.describe_db_instances()
            db_instances = [db['DBInstanceIdentifier'] for db in response['DBInstances']]
        
        if not db_instances:
            print("No RDS instances found.")
            return False
            
        widgets = []
        
        # Add title widget
        widgets.append({
            "type": "text",
            "x": 0,
            "y": 0,
            "width": 24,
            "height": 1,
            "properties": {
                "markdown": "# RDS Instances Dashboard\nCreated on " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        })
        
        # Add CPU utilization widget
        widgets.append({
            "type": "metric",
            "x": 0,
            "y": 1,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", db_instance ] for db_instance in db_instances
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "CPU Utilization",
                "period": 300,
                "stat": "Average"
            }
        })
        
        # Add database connections widget
        widgets.append({
            "type": "metric",
            "x": 12,
            "y": 1,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", db_instance ] for db_instance in db_instances
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Database Connections",
                "period": 300,
                "stat": "Average"
            }
        })
        
        # Add free storage space widget
        widgets.append({
            "type": "metric",
            "x": 0,
            "y": 7,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier", db_instance ] for db_instance in db_instances
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Free Storage Space",
                "period": 300,
                "stat": "Average"
            }
        })
        
        # Add read/write IOPS widget
        widgets.append({
            "type": "metric",
            "x": 12,
            "y": 7,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/RDS", "ReadIOPS", "DBInstanceIdentifier", db_instance ] for db_instance in db_instances
                ] + [
                    [ "AWS/RDS", "WriteIOPS", "DBInstanceIdentifier", db_instance ] for db_instance in db_instances
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Read/Write IOPS",
                "period": 300,
                "stat": "Average"
            }
        })
        
        # Add read/write latency widget
        widgets.append({
            "type": "metric",
            "x": 0,
            "y": 13,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/RDS", "ReadLatency", "DBInstanceIdentifier", db_instance ] for db_instance in db_instances
                ] + [
                    [ "AWS/RDS", "WriteLatency", "DBInstanceIdentifier", db_instance ] for db_instance in db_instances
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Read/Write Latency",
                "period": 300,
                "stat": "Average"
            }
        })
        
        # Add swap usage widget
        widgets.append({
            "type": "metric",
            "x": 12,
            "y": 13,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/RDS", "SwapUsage", "DBInstanceIdentifier", db_instance ] for db_instance in db_instances
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Swap Usage",
                "period": 300,
                "stat": "Average"
            }
        })
        
        dashboard_body = {
            "widgets": widgets
        }
        
        try:
            self.cloudwatch.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=json.dumps(dashboard_body)
            )
            print(f"Successfully created RDS dashboard: {dashboard_name}")
            return True
        except ClientError as e:
            print(f"Error creating dashboard: {e}")
            return False
    
    def create_lambda_dashboard(self, dashboard_name, function_names=None):
        """Create a CloudWatch dashboard for Lambda functions."""
        if not function_names:
            # Get all Lambda functions if none specified
            functions = []
            marker = None
            while True:
                if marker:
                    response = self.lambda_client.list_functions(Marker=marker)
                else:
                    response = self.lambda_client.list_functions()
                
                functions.extend(response['Functions'])
                
                if 'NextMarker' in response:
                    marker = response['NextMarker']
                else:
                    break
            
            function_names = [function['FunctionName'] for function in functions]
        
        if not function_names:
            print("No Lambda functions found.")
            return False
            
        widgets = []
        
        # Add title widget
        widgets.append({
            "type": "text",
            "x": 0,
            "y": 0,
            "width": 24,
            "height": 1,
            "properties": {
                "markdown": "# Lambda Functions Dashboard\nCreated on " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        })
        
        # Add invocations widget
        widgets.append({
            "type": "metric",
            "x": 0,
            "y": 1,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Invocations", "FunctionName", function_name ] for function_name in function_names
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Invocations",
                "period": 300,
                "stat": "Sum"
            }
        })
        
        # Add errors widget
        widgets.append({
            "type": "metric",
            "x": 12,
            "y": 1,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Errors", "FunctionName", function_name ] for function_name in function_names
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Errors",
                "period": 300,
                "stat": "Sum"
            }
        })
        
        # Add duration widget
        widgets.append({
            "type": "metric",
            "x": 0,
            "y": 7,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Duration", "FunctionName", function_name ] for function_name in function_names
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Duration",
                "period": 300,
                "stat": "Average"
            }
        })
        
        # Add throttles widget
        widgets.append({
            "type": "metric",
            "x": 12,
            "y": 7,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "Throttles", "FunctionName", function_name ] for function_name in function_names
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Throttles",
                "period": 300,
                "stat": "Sum"
            }
        })
        
        # Add concurrent executions widget
        widgets.append({
            "type": "metric",
            "x": 0,
            "y": 13,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "ConcurrentExecutions", "FunctionName", function_name ] for function_name in function_names
                ],
                "view": "timeSeries",
                "stacked": True,
                "region": self.region,
                "title": "Concurrent Executions",
                "period": 300,
                "stat": "Maximum"
            }
        })
        
        # Add iterator age widget (for stream-based invocations)
        widgets.append({
            "type": "metric",
            "x": 12,
            "y": 13,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/Lambda", "IteratorAge", "FunctionName", function_name ] for function_name in function_names
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Iterator Age",
                "period": 300,
                "stat": "Maximum"
            }
        })
        
        dashboard_body = {
            "widgets": widgets
        }
        
        try:
            self.cloudwatch.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=json.dumps(dashboard_body)
            )
            print(f"Successfully created Lambda dashboard: {dashboard_name}")
            return True
        except ClientError as e:
            print(f"Error creating dashboard: {e}")
            return False
    
    def create_alb_dashboard(self, dashboard_name, load_balancer_names=None):
        """Create a CloudWatch dashboard for Application Load Balancers."""
        if not load_balancer_names:
            # Get all ALBs if none specified
            response = self.elb.describe_load_balancers()
            load_balancer_names = []
            for lb in response['LoadBalancers']:
                if lb['Type'] == 'application':
                    load_balancer_names.append(lb['LoadBalancerName'])
                    
        if not load_balancer_names:
            print("No Application Load Balancers found.")
            return False
            
        widgets = []
        
        # Add title widget
        widgets.append({
            "type": "text",
            "x": 0,
            "y": 0,
            "width": 24,
            "height": 1,
            "properties": {
                "markdown": "# Application Load Balancer Dashboard\nCreated on " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        })
        
        # Add request count widget
        widgets.append({
            "type": "metric",
            "x": 0,
            "y": 1,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/ApplicationELB", "RequestCount", "LoadBalancer", lb_name ] for lb_name in load_balancer_names
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Request Count",
                "period": 300,
                "stat": "Sum"
            }
        })
        
        # Add target response time widget
        widgets.append({
            "type": "metric",
            "x": 12,
            "y": 1,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", lb_name ] for lb_name in load_balancer_names
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Target Response Time",
                "period": 300,
                "stat": "Average"
            }
        })
        
        # Add HTTP status codes widget
        widgets.append({
            "type": "metric",
            "x": 0,
            "y": 7,
            "width": 24,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/ApplicationELB", "HTTPCode_Target_2XX_Count", "LoadBalancer", lb_name ] for lb_name in load_balancer_names
                ] + [
                    [ "AWS/ApplicationELB", "HTTPCode_Target_3XX_Count", "LoadBalancer", lb_name ] for lb_name in load_balancer_names
                ] + [
                    [ "AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "LoadBalancer", lb_name ] for lb_name in load_balancer_names
                ] + [
                    [ "AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", lb_name ] for lb_name in load_balancer_names
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "HTTP Status Codes",
                "period": 300,
                "stat": "Sum"
            }
        })
        
        # Add healthy/unhealthy hosts widget
        widgets.append({
            "type": "metric",
            "x": 0,
            "y": 13,
            "width": 24,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/ApplicationELB", "HealthyHostCount", "LoadBalancer", lb_name ] for lb_name in load_balancer_names
                ] + [
                    [ "AWS/ApplicationELB", "UnHealthyHostCount", "LoadBalancer", lb_name ] for lb_name in load_balancer_names
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Healthy/Unhealthy Hosts",
                "period": 60,
                "stat": "Average"
            }
        })
        
        dashboard_body = {
            "widgets": widgets
        }
        
        try:
            self.cloudwatch.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=json.dumps(dashboard_body)
            )
            print(f"Successfully created ALB dashboard: {dashboard_name}")
            return True
        except ClientError as e:
            print(f"Error creating dashboard: {e}")
            return False
    
    def create_composite_dashboard(self, dashboard_name):
        """Create a composite dashboard with key metrics from multiple services."""
        widgets = []
        
        # Add title widget
        widgets.append({
            "type": "text",
            "x": 0,
            "y": 0,
            "width": 24,
            "height": 1,
            "properties": {
                "markdown": "# AWS Services Overview Dashboard\nCreated on " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        })
        
        # Get EC2 instances
        try:
            response = self.ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            ec2_instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    ec2_instances.append(instance['InstanceId'])
        except ClientError:
            ec2_instances = []
        
        # Get RDS instances
        try:
            response = self.rds.describe_db_instances()
            rds_instances = [db['DBInstanceIdentifier'] for db in response['DBInstances']]
        except ClientError:
            rds_instances = []
        
        # Get Lambda functions (top 5 by invocation)
        try:
            functions = []
            marker = None
            while True:
                if marker:
                    response = self.lambda_client.list_functions(Marker=marker)
                else:
                    response = self.lambda_client.list_functions()
                
                functions.extend(response['Functions'])
                
                if 'NextMarker' in response:
                    marker = response['NextMarker']
                else:
                    break
            
            lambda_functions = [function['FunctionName'] for function in functions[:5]]
        except ClientError:
            lambda_functions = []
        
        # Get ALBs
        try:
            response = self.elb.describe_load_balancers()
            albs = []
            for lb in response['LoadBalancers']:
                if lb['Type'] == 'application':
                    albs.append(lb['LoadBalancerName'])
        except ClientError:
            albs = []
        
        # Add EC2 CPU widget
        if ec2_instances:
            widgets.append({
                "type": "metric",
                "x": 0,
                "y": 1,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        [ "AWS/EC2", "CPUUtilization", "InstanceId", instance_id ] for instance_id in ec2_instances[:5]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": self.region,
                    "title": "EC2 CPU Utilization (Top 5)",
                    "period": 300,
                    "stat": "Average"
                }
            })
        
        # Add RDS CPU widget
        if rds_instances:
            widgets.append({
                "type": "metric",
                "x": 12,
                "y": 1,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        [ "AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", db_instance ] for db_instance in rds_instances[:5]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": self.region,
                    "title": "RDS CPU Utilization (Top 5)",
                    "period": 300,
                    "stat": "Average"
                }
            })
        
        # Add Lambda invocations widget
        if lambda_functions:
            widgets.append({
                "type": "metric",
                "x": 0,
                "y": 7,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        [ "AWS/Lambda", "Invocations", "FunctionName", function_name ] for function_name in lambda_functions
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": self.region,
                    "title": "Lambda Invocations (Top 5)",
                    "period": 300,
                    "stat": "Sum"
                }
            })
        
        # Add ALB requests widget
        if albs:
            widgets.append({
                "type": "metric",
                "x": 12,
                "y": 7,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        [ "AWS/ApplicationELB", "RequestCount", "LoadBalancer", lb_name ] for lb_name in albs[:5]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": self.region,
                    "title": "ALB Request Count (Top 5)",
                    "period": 300,
                    "stat": "Sum"
                }
            })
        
        # Add service health widget
        widgets.append({
            "type": "metric",
            "x": 0,
            "y": 13,
            "width": 24,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/EC2", "StatusCheckFailed", "InstanceId", instance_id ] for instance_id in ec2_instances[:5]
                ] + [
                    [ "AWS/Lambda", "Errors", "FunctionName", function_name ] for function_name in lambda_functions[:5]
                ] + [
                    [ "AWS/ApplicationELB", "UnHealthyHostCount", "LoadBalancer", lb_name ] for lb_name in albs[:5]
                ],
                "view": "timeSeries",
                "stacked": False,
                "region": self.region,
                "title": "Service Health Issues",
                "period": 300,
                "stat": "Sum"
            }
        })
        
        dashboard_body = {
            "widgets": widgets
        }
        
        try:
            self.cloudwatch.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=json.dumps(dashboard_body)
            )
            print(f"Successfully created composite dashboard: {dashboard_name}")
            return True
        except ClientError as e:
            print(f"Error creating dashboard: {e}")
            return False
    
    def list_dashboards(self):
        """List all CloudWatch dashboards."""
        try:
            response = self.cloudwatch.list_dashboards()
            if not response['DashboardEntries']:
                print("No dashboards found.")
                return []
            
            print("\nAvailable dashboards:")
            for dashboard in response['DashboardEntries']:
                print(f"- {dashboard['DashboardName']}")
            
            return [dashboard['DashboardName'] for dashboard in response['DashboardEntries']]
        except ClientError as e:
            print(f"Error listing dashboards: {e}")
            return []
    
    def delete_dashboard(self, dashboard_name):
        """Delete a CloudWatch dashboard."""
        try:
            self.cloudwatch.delete_dashboards(DashboardNames=[dashboard_name])
            print(f"Successfully deleted dashboard: {dashboard_name}")
            return True
        except ClientError as e:
            print(f"Error deleting dashboard: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='CloudWatch Dashboard Creator')
    parser.add_argument('--region', help='AWS region')
    parser.add_argument('--profile', help='AWS profile')
    parser.add_argument('--action', choices=['create', 'list', 'delete'], default='create', help='Action to perform')
    parser.add_argument('--type', choices=['ec2', 'rds', 'lambda', 'alb', 'composite'], help='Dashboard type')
    parser.add_argument('--name', help='Dashboard name')
    parser.add_argument('--resources', nargs='+', help='Resource IDs (e.g., instance IDs, function names)')
    
    args = parser.parse_args()
    
    dashboard_creator = CloudWatchDashboardCreator(region=args.region, profile=args.profile)
    
    if args.action == 'list':
        dashboard_creator.list_dashboards()
        return
    
    if args.action == 'delete':
        if not args.name:
            print("Error: Dashboard name is required for delete action")
            return
        dashboard_creator.delete_dashboard(args.name)
        return
    
    if args.action == 'create':
        if not args.type:
            print("Error: Dashboard type is required for create action")
            return
        
        if not args.name:
            timestamp = int(time.time())
            args.name = f"{args.type}-dashboard-{timestamp}"
        
        if args.type == 'ec2':
            dashboard_creator.create_ec2_dashboard(args.name, args.resources)
        elif args.type == 'rds':
            dashboard_creator.create_rds_dashboard(args.name, args.resources)
        elif args.type == 'lambda':
            dashboard_creator.create_lambda_dashboard(args.name, args.resources)
        elif args.type == 'alb':
            dashboard_creator.create_alb_dashboard(args.name, args.resources)
        elif args.type == 'composite':
            dashboard_creator.create_composite_dashboard(args.name)

if __name__ == '__main__':
    main()
