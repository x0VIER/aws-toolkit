#!/usr/bin/env python3
"""
Resource Rightsizer

This script analyzes AWS resource utilization and provides recommendations for rightsizing
to optimize costs while maintaining performance.

Author: V Vier
"""

import argparse
import boto3
import json
import sys
import csv
import os
from datetime import datetime, timedelta
from tabulate import tabulate
from botocore.exceptions import ClientError

class ResourceRightsizer:
    def __init__(self, region=None, profile=None):
        """Initialize the Resource Rightsizer with optional region and profile."""
        session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
        self.ec2 = session.client('ec2')
        self.cloudwatch = session.client('cloudwatch')
        self.rds = session.client('rds')
        self.dynamodb = session.client('dynamodb')
        self.elasticache = session.client('elasticache')
        self.region = region or session.region_name
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        
    def analyze_ec2_instances(self, days=14, threshold=30):
        """Analyze EC2 instances for rightsizing opportunities."""
        print(f"Analyzing EC2 instances for the past {days} days with utilization threshold of {threshold}%...")
        
        # Get all running instances
        try:
            response = self.ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            
            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances.append(instance)
            
            if not instances:
                print("No running EC2 instances found.")
                return []
            
            # Get instance types information
            instance_types = {}
            paginator = self.ec2.get_paginator('describe_instance_types')
            for page in paginator.paginate():
                for instance_type in page['InstanceTypes']:
                    instance_types[instance_type['InstanceType']] = {
                        'vCPU': instance_type['VCpuInfo']['DefaultVCpus'],
                        'Memory': instance_type['MemoryInfo']['SizeInMiB'] / 1024  # Convert to GB
                    }
            
            # Analyze each instance
            recommendations = []
            
            for instance in instances:
                instance_id = instance['InstanceId']
                instance_type = instance['InstanceType']
                
                # Get instance name from tags
                instance_name = "Unnamed"
                if 'Tags' in instance:
                    for tag in instance['Tags']:
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break
                
                # Get CPU utilization metrics
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(days=days)
                
                try:
                    cpu_response = self.cloudwatch.get_metric_statistics(
                        Namespace='AWS/EC2',
                        MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,  # 1 hour
                        Statistics=['Average', 'Maximum']
                    )
                    
                    if not cpu_response['Datapoints']:
                        print(f"No CPU utilization data available for instance {instance_id}. Skipping...")
                        continue
                    
                    # Calculate average and maximum CPU utilization
                    avg_cpu = sum(point['Average'] for point in cpu_response['Datapoints']) / len(cpu_response['Datapoints'])
                    max_cpu = max(point['Maximum'] for point in cpu_response['Datapoints'])
                    
                    # Get current instance specs
                    current_vcpu = instance_types.get(instance_type, {}).get('vCPU', 0)
                    current_memory = instance_types.get(instance_type, {}).get('Memory', 0)
                    
                    # Determine if instance is underutilized
                    if avg_cpu < threshold and max_cpu < threshold * 1.5:
                        # Find recommended instance type
                        recommended_type = self.recommend_instance_type(instance_type, avg_cpu, max_cpu)
                        
                        if recommended_type and recommended_type != instance_type:
                            # Get recommended instance specs
                            recommended_vcpu = instance_types.get(recommended_type, {}).get('vCPU', 0)
                            recommended_memory = instance_types.get(recommended_type, {}).get('Memory', 0)
                            
                            # Calculate estimated savings
                            current_price = self.get_instance_price(instance_type)
                            recommended_price = self.get_instance_price(recommended_type)
                            monthly_savings = (current_price - recommended_price) * 24 * 30  # 30 days
                            
                            recommendations.append({
                                'ResourceId': instance_id,
                                'ResourceName': instance_name,
                                'ResourceType': 'EC2 Instance',
                                'CurrentConfiguration': instance_type,
                                'RecommendedConfiguration': recommended_type,
                                'CurrentVCPU': current_vcpu,
                                'RecommendedVCPU': recommended_vcpu,
                                'CurrentMemory': f"{current_memory:.1f} GB",
                                'RecommendedMemory': f"{recommended_memory:.1f} GB",
                                'AverageCPUUtilization': f"{avg_cpu:.2f}%",
                                'MaxCPUUtilization': f"{max_cpu:.2f}%",
                                'EstimatedMonthlySavings': f"${monthly_savings:.2f}",
                                'Region': self.region
                            })
                
                except ClientError as e:
                    print(f"Error getting metrics for instance {instance_id}: {e}")
            
            return recommendations
            
        except ClientError as e:
            print(f"Error analyzing EC2 instances: {e}")
            return []
    
    def recommend_instance_type(self, current_type, avg_cpu, max_cpu):
        """Recommend a new instance type based on utilization."""
        # Define instance type families and their sizes
        instance_families = {
            't2': ['t2.nano', 't2.micro', 't2.small', 't2.medium', 't2.large', 't2.xlarge', 't2.2xlarge'],
            't3': ['t3.nano', 't3.micro', 't3.small', 't3.medium', 't3.large', 't3.xlarge', 't3.2xlarge'],
            't3a': ['t3a.nano', 't3a.micro', 't3a.small', 't3a.medium', 't3a.large', 't3a.xlarge', 't3a.2xlarge'],
            't4g': ['t4g.nano', 't4g.micro', 't4g.small', 't4g.medium', 't4g.large', 't4g.xlarge', 't4g.2xlarge'],
            'm5': ['m5.large', 'm5.xlarge', 'm5.2xlarge', 'm5.4xlarge', 'm5.8xlarge', 'm5.12xlarge', 'm5.16xlarge', 'm5.24xlarge'],
            'm5a': ['m5a.large', 'm5a.xlarge', 'm5a.2xlarge', 'm5a.4xlarge', 'm5a.8xlarge', 'm5a.12xlarge', 'm5a.16xlarge', 'm5a.24xlarge'],
            'm6g': ['m6g.medium', 'm6g.large', 'm6g.xlarge', 'm6g.2xlarge', 'm6g.4xlarge', 'm6g.8xlarge', 'm6g.12xlarge', 'm6g.16xlarge'],
            'c5': ['c5.large', 'c5.xlarge', 'c5.2xlarge', 'c5.4xlarge', 'c5.9xlarge', 'c5.12xlarge', 'c5.18xlarge', 'c5.24xlarge'],
            'r5': ['r5.large', 'r5.xlarge', 'r5.2xlarge', 'r5.4xlarge', 'r5.8xlarge', 'r5.12xlarge', 'r5.16xlarge', 'r5.24xlarge'],
        }
        
        # Find the family and size of the current instance
        current_family = None
        current_size_index = -1
        
        for family, sizes in instance_families.items():
            if current_type in sizes:
                current_family = family
                current_size_index = sizes.index(current_type)
                break
        
        if current_family is None or current_size_index == -1:
            # Unknown instance type or family
            return None
        
        # Determine the recommended size based on CPU utilization
        if avg_cpu < 5:
            # Severely underutilized, recommend going down 2 sizes if possible
            recommended_size_index = max(0, current_size_index - 2)
        elif avg_cpu < 20:
            # Underutilized, recommend going down 1 size if possible
            recommended_size_index = max(0, current_size_index - 1)
        else:
            # Utilization is acceptable, no change needed
            return current_type
        
        # Get the recommended instance type
        recommended_type = instance_families[current_family][recommended_size_index]
        
        return recommended_type
    
    def get_instance_price(self, instance_type):
        """Get the approximate price for an instance type."""
        # This is a simplified pricing model for demonstration purposes
        # In a real implementation, you would use the AWS Price List API or a pricing database
        pricing = {
            't2.nano': 0.0058,
            't2.micro': 0.0116,
            't2.small': 0.023,
            't2.medium': 0.0464,
            't2.large': 0.0928,
            't2.xlarge': 0.1856,
            't2.2xlarge': 0.3712,
            't3.nano': 0.0052,
            't3.micro': 0.0104,
            't3.small': 0.0208,
            't3.medium': 0.0416,
            't3.large': 0.0832,
            't3.xlarge': 0.1664,
            't3.2xlarge': 0.3328,
            't3a.nano': 0.0047,
            't3a.micro': 0.0094,
            't3a.small': 0.0188,
            't3a.medium': 0.0376,
            't3a.large': 0.0752,
            't3a.xlarge': 0.1504,
            't3a.2xlarge': 0.3008,
            't4g.nano': 0.0042,
            't4g.micro': 0.0084,
            't4g.small': 0.0168,
            't4g.medium': 0.0336,
            't4g.large': 0.0672,
            't4g.xlarge': 0.1344,
            't4g.2xlarge': 0.2688,
            'm5.large': 0.096,
            'm5.xlarge': 0.192,
            'm5.2xlarge': 0.384,
            'm5.4xlarge': 0.768,
            'm5.8xlarge': 1.536,
            'm5.12xlarge': 2.304,
            'm5.16xlarge': 3.072,
            'm5.24xlarge': 4.608,
            'c5.large': 0.085,
            'c5.xlarge': 0.17,
            'c5.2xlarge': 0.34,
            'c5.4xlarge': 0.68,
            'c5.9xlarge': 1.53,
            'r5.large': 0.126,
            'r5.xlarge': 0.252,
            'r5.2xlarge': 0.504,
            'r5.4xlarge': 1.008,
            'r5.8xlarge': 2.016,
        }
        
        return pricing.get(instance_type, 0.0)
    
    def analyze_rds_instances(self, days=14, threshold=30):
        """Analyze RDS instances for rightsizing opportunities."""
        print(f"Analyzing RDS instances for the past {days} days with utilization threshold of {threshold}%...")
        
        # Get all RDS instances
        try:
            response = self.rds.describe_db_instances()
            
            instances = response['DBInstances']
            
            if not instances:
                print("No RDS instances found.")
                return []
            
            # Analyze each instance
            recommendations = []
            
            for instance in instances:
                instance_id = instance['DBInstanceIdentifier']
                instance_class = instance['DBInstanceClass']
                engine = instance['Engine']
                
                # Get CPU utilization metrics
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(days=days)
                
                try:
                    cpu_response = self.cloudwatch.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': instance_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,  # 1 hour
                        Statistics=['Average', 'Maximum']
                    )
                    
                    if not cpu_response['Datapoints']:
                        print(f"No CPU utilization data available for RDS instance {instance_id}. Skipping...")
                        continue
                    
                    # Calculate average and maximum CPU utilization
                    avg_cpu = sum(point['Average'] for point in cpu_response['Datapoints']) / len(cpu_response['Datapoints'])
                    max_cpu = max(point['Maximum'] for point in cpu_response['Datapoints'])
                    
                    # Get memory utilization metrics if available
                    memory_utilization = "N/A"
                    try:
                        memory_response = self.cloudwatch.get_metric_statistics(
                            Namespace='AWS/RDS',
                            MetricName='FreeableMemory',
                            Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': instance_id}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=3600,  # 1 hour
                            Statistics=['Average']
                        )
                        
                        if memory_response['Datapoints']:
                            # Estimate total memory based on instance class
                            total_memory = self.get_rds_memory(instance_class)
                            if total_memory > 0:
                                avg_freeable_memory = sum(point['Average'] for point in memory_response['Datapoints']) / len(memory_response['Datapoints'])
                                memory_utilization = f"{(1 - (avg_freeable_memory / (total_memory * 1024 * 1024 * 1024))) * 100:.2f}%"
                    except ClientError:
                        pass
                    
                    # Determine if instance is underutilized
                    if avg_cpu < threshold and max_cpu < threshold * 1.5:
                        # Find recommended instance class
                        recommended_class = self.recommend_rds_instance_class(instance_class, avg_cpu, max_cpu)
                        
                        if recommended_class and recommended_class != instance_class:
                            # Calculate estimated savings
                            current_price = self.get_rds_price(instance_class, engine)
                            recommended_price = self.get_rds_price(recommended_class, engine)
                            monthly_savings = (current_price - recommended_price) * 24 * 30  # 30 days
                            
                            recommendations.append({
                                'ResourceId': instance_id,
                                'ResourceName': instance_id,
                                'ResourceType': 'RDS Instance',
                                'Engine': engine,
                                'CurrentConfiguration': instance_class,
                                'RecommendedConfiguration': recommended_class,
                                'AverageCPUUtilization': f"{avg_cpu:.2f}%",
                                'MaxCPUUtilization': f"{max_cpu:.2f}%",
                                'MemoryUtilization': memory_utilization,
                                'EstimatedMonthlySavings': f"${monthly_savings:.2f}",
                                'Region': self.region
                            })
                
                except ClientError as e:
                    print(f"Error getting metrics for RDS instance {instance_id}: {e}")
            
            return recommendations
            
        except ClientError as e:
            print(f"Error analyzing RDS instances: {e}")
            return []
    
    def get_rds_memory(self, instance_class):
        """Get the memory (in GB) for an RDS instance class."""
        # This is a simplified mapping for demonstration purposes
        memory_map = {
            'db.t3.micro': 1,
            'db.t3.small': 2,
            'db.t3.medium': 4,
            'db.t3.large': 8,
            'db.t3.xlarge': 16,
            'db.t3.2xlarge': 32,
            'db.m5.large': 8,
            'db.m5.xlarge': 16,
            'db.m5.2xlarge': 32,
            'db.m5.4xlarge': 64,
            'db.m5.8xlarge': 128,
            'db.m5.12xlarge': 192,
            'db.m5.16xlarge': 256,
            'db.m5.24xlarge': 384,
            'db.r5.large': 16,
            'db.r5.xlarge': 32,
            'db.r5.2xlarge': 64,
            'db.r5.4xlarge': 128,
            'db.r5.8xlarge': 256,
            'db.r5.12xlarge': 384,
            'db.r5.16xlarge': 512,
            'db.r5.24xlarge': 768,
        }
        
        return memory_map.get(instance_class, 0)
    
    def recommend_rds_instance_class(self, current_class, avg_cpu, max_cpu):
        """Recommend a new RDS instance class based on utilization."""
        # Define instance class families and their sizes
        instance_families = {
            'db.t3': ['db.t3.micro', 'db.t3.small', 'db.t3.medium', 'db.t3.large', 'db.t3.xlarge', 'db.t3.2xlarge'],
            'db.m5': ['db.m5.large', 'db.m5.xlarge', 'db.m5.2xlarge', 'db.m5.4xlarge', 'db.m5.8xlarge', 'db.m5.12xlarge', 'db.m5.16xlarge', 'db.m5.24xlarge'],
            'db.r5': ['db.r5.large', 'db.r5.xlarge', 'db.r5.2xlarge', 'db.r5.4xlarge', 'db.r5.8xlarge', 'db.r5.12xlarge', 'db.r5.16xlarge', 'db.r5.24xlarge'],
        }
        
        # Find the family and size of the current instance
        current_family = None
        current_size_index = -1
        
        for family, sizes in instance_families.items():
            if current_class in sizes:
                current_family = family
                current_size_index = sizes.index(current_class)
                break
        
        if current_family is None or current_size_index == -1:
            # Unknown instance class or family
            return None
        
        # Determine the recommended size based on CPU utilization
        if avg_cpu < 5:
            # Severely underutilized, recommend going down 2 sizes if possible
            recommended_size_index = max(0, current_size_index - 2)
        elif avg_cpu < 20:
            # Underutilized, recommend going down 1 size if possible
            recommended_size_index = max(0, current_size_index - 1)
        else:
            # Utilization is acceptable, no change needed
            return current_class
        
        # Get the recommended instance class
        recommended_class = instance_families[current_family][recommended_size_index]
        
        return recommended_class
    
    def get_rds_price(self, instance_class, engine):
        """Get the approximate price for an RDS instance class."""
        # This is a simplified pricing model for demonstration purposes
        # In a real implementation, you would use the AWS Price List API or a pricing database
        pricing = {
            'db.t3.micro': 0.018,
            'db.t3.small': 0.036,
            'db.t3.medium': 0.072,
            'db.t3.large': 0.144,
            'db.t3.xlarge': 0.288,
            'db.t3.2xlarge': 0.576,
            'db.m5.large': 0.171,
            'db.m5.xlarge': 0.342,
            'db.m5.2xlarge': 0.684,
            'db.m5.4xlarge': 1.368,
            'db.m5.8xlarge': 2.736,
            'db.m5.12xlarge': 4.104,
            'db.m5.16xlarge': 5.472,
            'db.m5.24xlarge': 8.208,
            'db.r5.large': 0.226,
            'db.r5.xlarge': 0.452,
            'db.r5.2xlarge': 0.904,
            'db.r5.4xlarge': 1.808,
            'db.r5.8xlarge': 3.616,
            'db.r5.12xlarge': 5.424,
            'db.r5.16xlarge': 7.232,
            'db.r5.24xlarge': 10.848,
        }
        
        # Apply engine-specific multiplier
        multiplier = 1.0
        if engine == 'oracle-se2':
            multiplier = 1.5
        elif engine == 'sqlserver-se':
            multiplier = 1.7
        
        return pricing.get(instance_class, 0.0) * multiplier
    
    def analyze_dynamodb_tables(self, days=14):
        """Analyze DynamoDB tables for rightsizing opportunities."""
        print(f"Analyzing DynamoDB tables for the past {days} days...")
        
        # Get all DynamoDB tables
        try:
            response = self.dynamodb.list_tables()
            table_names = response['TableNames']
            
            if not table_names:
                print("No DynamoDB tables found.")
                return []
            
            # Analyze each table
            recommendations = []
            
            for table_name in table_names:
                # Get table details
                table_response = self.dynamodb.describe_table(TableName=table_name)
                table = table_response['Table']
                
                # Check if table is using provisioned capacity
                if 'ProvisionedThroughput' not in table:
                    # Table is using on-demand capacity
                    continue
                
                provisioned_read = table['ProvisionedThroughput']['ReadCapacityUnits']
                provisioned_write = table['ProvisionedThroughput']['WriteCapacityUnits']
                
                # Get consumed capacity metrics
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(days=days)
                
                try:
                    # Get consumed read capacity
                    read_response = self.cloudwatch.get_metric_statistics(
                        Namespace='AWS/DynamoDB',
                        MetricName='ConsumedReadCapacityUnits',
                        Dimensions=[{'Name': 'TableName', 'Value': table_name}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,  # 1 hour
                        Statistics=['Sum']
                    )
                    
                    # Get consumed write capacity
                    write_response = self.cloudwatch.get_metric_statistics(
                        Namespace='AWS/DynamoDB',
                        MetricName='ConsumedWriteCapacityUnits',
                        Dimensions=[{'Name': 'TableName', 'Value': table_name}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,  # 1 hour
                        Statistics=['Sum']
                    )
                    
                    if not read_response['Datapoints'] or not write_response['Datapoints']:
                        print(f"No capacity utilization data available for DynamoDB table {table_name}. Skipping...")
                        continue
                    
                    # Calculate average consumed capacity
                    avg_read = max(1, sum(point['Sum'] for point in read_response['Datapoints']) / len(read_response['Datapoints']) / 3600)
                    avg_write = max(1, sum(point['Sum'] for point in write_response['Datapoints']) / len(write_response['Datapoints']) / 3600)
                    
                    # Calculate utilization percentage
                    read_utilization = (avg_read / provisioned_read) * 100
                    write_utilization = (avg_write / provisioned_write) * 100
                    
                    # Determine if table is overprovisioned
                    if read_utilization < 20 or write_utilization < 20:
                        # Calculate recommended capacity
                        recommended_read = max(1, int(avg_read * 1.5))  # Add 50% buffer
                        recommended_write = max(1, int(avg_write * 1.5))  # Add 50% buffer
                        
                        # Calculate estimated savings
                        current_cost = (provisioned_read * 0.00013 + provisioned_write * 0.00065) * 24 * 30  # 30 days
                        recommended_cost = (recommended_read * 0.00013 + recommended_write * 0.00065) * 24 * 30  # 30 days
                        monthly_savings = current_cost - recommended_cost
                        
                        # Check if on-demand would be cheaper
                        estimated_on_demand_cost = (avg_read * 0.25 / 1000000 + avg_write * 1.25 / 1000000) * 24 * 30  # 30 days
                        
                        recommendations.append({
                            'ResourceId': table_name,
                            'ResourceName': table_name,
                            'ResourceType': 'DynamoDB Table',
                            'CurrentReadCapacity': provisioned_read,
                            'CurrentWriteCapacity': provisioned_write,
                            'AverageReadCapacity': f"{avg_read:.2f}",
                            'AverageWriteCapacity': f"{avg_write:.2f}",
                            'ReadUtilization': f"{read_utilization:.2f}%",
                            'WriteUtilization': f"{write_utilization:.2f}%",
                            'RecommendedReadCapacity': recommended_read,
                            'RecommendedWriteCapacity': recommended_write,
                            'EstimatedMonthlySavings': f"${monthly_savings:.2f}",
                            'ConsiderOnDemand': 'Yes' if estimated_on_demand_cost < recommended_cost else 'No',
                            'Region': self.region
                        })
                
                except ClientError as e:
                    print(f"Error getting metrics for DynamoDB table {table_name}: {e}")
            
            return recommendations
            
        except ClientError as e:
            print(f"Error analyzing DynamoDB tables: {e}")
            return []
    
    def analyze_elasticache_clusters(self, days=14, threshold=30):
        """Analyze ElastiCache clusters for rightsizing opportunities."""
        print(f"Analyzing ElastiCache clusters for the past {days} days with utilization threshold of {threshold}%...")
        
        # Get all ElastiCache clusters
        try:
            response = self.elasticache.describe_cache_clusters()
            clusters = response['CacheClusters']
            
            if not clusters:
                print("No ElastiCache clusters found.")
                return []
            
            # Analyze each cluster
            recommendations = []
            
            for cluster in clusters:
                cluster_id = cluster['CacheClusterId']
                node_type = cluster['CacheNodeType']
                engine = cluster['Engine']
                
                # Get CPU utilization metrics
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(days=days)
                
                try:
                    cpu_response = self.cloudwatch.get_metric_statistics(
                        Namespace='AWS/ElastiCache',
                        MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'CacheClusterId', 'Value': cluster_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,  # 1 hour
                        Statistics=['Average', 'Maximum']
                    )
                    
                    if not cpu_response['Datapoints']:
                        print(f"No CPU utilization data available for ElastiCache cluster {cluster_id}. Skipping...")
                        continue
                    
                    # Calculate average and maximum CPU utilization
                    avg_cpu = sum(point['Average'] for point in cpu_response['Datapoints']) / len(cpu_response['Datapoints'])
                    max_cpu = max(point['Maximum'] for point in cpu_response['Datapoints'])
                    
                    # Get memory utilization metrics
                    memory_response = self.cloudwatch.get_metric_statistics(
                        Namespace='AWS/ElastiCache',
                        MetricName='DatabaseMemoryUsagePercentage',
                        Dimensions=[{'Name': 'CacheClusterId', 'Value': cluster_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,  # 1 hour
                        Statistics=['Average', 'Maximum']
                    )
                    
                    memory_utilization = "N/A"
                    max_memory_utilization = "N/A"
                    
                    if memory_response['Datapoints']:
                        avg_memory = sum(point['Average'] for point in memory_response['Datapoints']) / len(memory_response['Datapoints'])
                        max_memory = max(point['Maximum'] for point in memory_response['Datapoints'])
                        memory_utilization = f"{avg_memory:.2f}%"
                        max_memory_utilization = f"{max_memory:.2f}%"
                    
                    # Determine if cluster is underutilized
                    if avg_cpu < threshold and max_cpu < threshold * 1.5:
                        # Find recommended node type
                        recommended_type = self.recommend_elasticache_node_type(node_type, avg_cpu, max_cpu)
                        
                        if recommended_type and recommended_type != node_type:
                            # Calculate estimated savings
                            current_price = self.get_elasticache_price(node_type, engine)
                            recommended_price = self.get_elasticache_price(recommended_type, engine)
                            monthly_savings = (current_price - recommended_price) * 24 * 30  # 30 days
                            
                            recommendations.append({
                                'ResourceId': cluster_id,
                                'ResourceName': cluster_id,
                                'ResourceType': 'ElastiCache Cluster',
                                'Engine': engine,
                                'CurrentConfiguration': node_type,
                                'RecommendedConfiguration': recommended_type,
                                'AverageCPUUtilization': f"{avg_cpu:.2f}%",
                                'MaxCPUUtilization': f"{max_cpu:.2f}%",
                                'AverageMemoryUtilization': memory_utilization,
                                'MaxMemoryUtilization': max_memory_utilization,
                                'EstimatedMonthlySavings': f"${monthly_savings:.2f}",
                                'Region': self.region
                            })
                
                except ClientError as e:
                    print(f"Error getting metrics for ElastiCache cluster {cluster_id}: {e}")
            
            return recommendations
            
        except ClientError as e:
            print(f"Error analyzing ElastiCache clusters: {e}")
            return []
    
    def recommend_elasticache_node_type(self, current_type, avg_cpu, max_cpu):
        """Recommend a new ElastiCache node type based on utilization."""
        # Define node type families and their sizes
        node_families = {
            'cache.t3': ['cache.t3.micro', 'cache.t3.small', 'cache.t3.medium'],
            'cache.m5': ['cache.m5.large', 'cache.m5.xlarge', 'cache.m5.2xlarge', 'cache.m5.4xlarge', 'cache.m5.12xlarge', 'cache.m5.24xlarge'],
            'cache.r5': ['cache.r5.large', 'cache.r5.xlarge', 'cache.r5.2xlarge', 'cache.r5.4xlarge', 'cache.r5.12xlarge', 'cache.r5.24xlarge'],
        }
        
        # Find the family and size of the current node
        current_family = None
        current_size_index = -1
        
        for family, sizes in node_families.items():
            if current_type in sizes:
                current_family = family
                current_size_index = sizes.index(current_type)
                break
        
        if current_family is None or current_size_index == -1:
            # Unknown node type or family
            return None
        
        # Determine the recommended size based on CPU utilization
        if avg_cpu < 5:
            # Severely underutilized, recommend going down 2 sizes if possible
            recommended_size_index = max(0, current_size_index - 2)
        elif avg_cpu < 20:
            # Underutilized, recommend going down 1 size if possible
            recommended_size_index = max(0, current_size_index - 1)
        else:
            # Utilization is acceptable, no change needed
            return current_type
        
        # Get the recommended node type
        recommended_type = node_families[current_family][recommended_size_index]
        
        return recommended_type
    
    def get_elasticache_price(self, node_type, engine):
        """Get the approximate price for an ElastiCache node type."""
        # This is a simplified pricing model for demonstration purposes
        # In a real implementation, you would use the AWS Price List API or a pricing database
        pricing = {
            'cache.t3.micro': 0.018,
            'cache.t3.small': 0.036,
            'cache.t3.medium': 0.068,
            'cache.m5.large': 0.136,
            'cache.m5.xlarge': 0.271,
            'cache.m5.2xlarge': 0.542,
            'cache.m5.4xlarge': 1.084,
            'cache.m5.12xlarge': 3.252,
            'cache.m5.24xlarge': 6.504,
            'cache.r5.large': 0.216,
            'cache.r5.xlarge': 0.432,
            'cache.r5.2xlarge': 0.864,
            'cache.r5.4xlarge': 1.728,
            'cache.r5.12xlarge': 5.184,
            'cache.r5.24xlarge': 10.368,
        }
        
        # Apply engine-specific multiplier
        multiplier = 1.0
        if engine == 'redis':
            multiplier = 1.1  # Redis is slightly more expensive than Memcached
        
        return pricing.get(node_type, 0.0) * multiplier
    
    def analyze_all_resources(self, days=14, threshold=30):
        """Analyze all resources for rightsizing opportunities."""
        all_recommendations = []
        
        # Analyze EC2 instances
        ec2_recommendations = self.analyze_ec2_instances(days, threshold)
        all_recommendations.extend(ec2_recommendations)
        
        # Analyze RDS instances
        rds_recommendations = self.analyze_rds_instances(days, threshold)
        all_recommendations.extend(rds_recommendations)
        
        # Analyze DynamoDB tables
        dynamodb_recommendations = self.analyze_dynamodb_tables(days)
        all_recommendations.extend(dynamodb_recommendations)
        
        # Analyze ElastiCache clusters
        elasticache_recommendations = self.analyze_elasticache_clusters(days, threshold)
        all_recommendations.extend(elasticache_recommendations)
        
        return all_recommendations
    
    def print_results(self, recommendations, format='table'):
        """Print the results in the specified format."""
        if not recommendations:
            print("No rightsizing recommendations found.")
            return
        
        # Calculate total estimated savings
        total_savings = 0.0
        for rec in recommendations:
            savings_str = rec.get('EstimatedMonthlySavings', '$0.00')
            if isinstance(savings_str, str) and savings_str.startswith('$'):
                total_savings += float(savings_str[1:])
        
        print(f"\nTotal estimated monthly savings: ${total_savings:.2f}")
        print(f"Total recommendations: {len(recommendations)}")
        
        if format == 'table':
            # Prepare table data based on resource type
            ec2_recs = [r for r in recommendations if r['ResourceType'] == 'EC2 Instance']
            rds_recs = [r for r in recommendations if r['ResourceType'] == 'RDS Instance']
            dynamodb_recs = [r for r in recommendations if r['ResourceType'] == 'DynamoDB Table']
            elasticache_recs = [r for r in recommendations if r['ResourceType'] == 'ElastiCache Cluster']
            
            # Print EC2 recommendations
            if ec2_recs:
                print("\nEC2 Instance Recommendations:")
                headers = ['Instance ID', 'Name', 'Current Type', 'Recommended Type', 'Avg CPU', 'Max CPU', 'Est. Monthly Savings']
                table_data = []
                
                for rec in ec2_recs:
                    table_data.append([
                        rec['ResourceId'],
                        rec['ResourceName'],
                        rec['CurrentConfiguration'],
                        rec['RecommendedConfiguration'],
                        rec['AverageCPUUtilization'],
                        rec['MaxCPUUtilization'],
                        rec['EstimatedMonthlySavings']
                    ])
                
                print(tabulate(table_data, headers=headers, tablefmt='grid'))
            
            # Print RDS recommendations
            if rds_recs:
                print("\nRDS Instance Recommendations:")
                headers = ['Instance ID', 'Engine', 'Current Class', 'Recommended Class', 'Avg CPU', 'Est. Monthly Savings']
                table_data = []
                
                for rec in rds_recs:
                    table_data.append([
                        rec['ResourceId'],
                        rec['Engine'],
                        rec['CurrentConfiguration'],
                        rec['RecommendedConfiguration'],
                        rec['AverageCPUUtilization'],
                        rec['EstimatedMonthlySavings']
                    ])
                
                print(tabulate(table_data, headers=headers, tablefmt='grid'))
            
            # Print DynamoDB recommendations
            if dynamodb_recs:
                print("\nDynamoDB Table Recommendations:")
                headers = ['Table Name', 'Current Read', 'Current Write', 'Recommended Read', 'Recommended Write', 'Est. Monthly Savings', 'Consider On-Demand']
                table_data = []
                
                for rec in dynamodb_recs:
                    table_data.append([
                        rec['ResourceName'],
                        rec['CurrentReadCapacity'],
                        rec['CurrentWriteCapacity'],
                        rec['RecommendedReadCapacity'],
                        rec['RecommendedWriteCapacity'],
                        rec['EstimatedMonthlySavings'],
                        rec['ConsiderOnDemand']
                    ])
                
                print(tabulate(table_data, headers=headers, tablefmt='grid'))
            
            # Print ElastiCache recommendations
            if elasticache_recs:
                print("\nElastiCache Cluster Recommendations:")
                headers = ['Cluster ID', 'Engine', 'Current Type', 'Recommended Type', 'Avg CPU', 'Avg Memory', 'Est. Monthly Savings']
                table_data = []
                
                for rec in elasticache_recs:
                    table_data.append([
                        rec['ResourceId'],
                        rec['Engine'],
                        rec['CurrentConfiguration'],
                        rec['RecommendedConfiguration'],
                        rec['AverageCPUUtilization'],
                        rec['AverageMemoryUtilization'],
                        rec['EstimatedMonthlySavings']
                    ])
                
                print(tabulate(table_data, headers=headers, tablefmt='grid'))
            
        elif format == 'json':
            print(json.dumps(recommendations, indent=2, default=str))
            
        elif format == 'csv':
            # Get all possible keys
            all_keys = set()
            for rec in recommendations:
                all_keys.update(rec.keys())
            
            # Print CSV to stdout
            writer = csv.DictWriter(sys.stdout, fieldnames=sorted(all_keys))
            writer.writeheader()
            for rec in recommendations:
                writer.writerow(rec)
    
    def export_results(self, recommendations, filename, format='json'):
        """Export the results to a file in the specified format."""
        if not recommendations:
            print("No rightsizing recommendations found to export.")
            return
        
        try:
            if format == 'json':
                with open(filename, 'w') as f:
                    json.dump(recommendations, f, indent=2, default=str)
                    
            elif format == 'csv':
                # Get all possible keys
                all_keys = set()
                for rec in recommendations:
                    all_keys.update(rec.keys())
                
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=sorted(all_keys))
                    writer.writeheader()
                    for rec in recommendations:
                        writer.writerow(rec)
            
            elif format == 'html':
                # Create an HTML report
                html_content = self.generate_html_report(recommendations)
                
                with open(filename, 'w') as f:
                    f.write(html_content)
            
            print(f"Results exported to {filename}")
            
        except Exception as e:
            print(f"Error exporting results: {e}")
    
    def generate_html_report(self, recommendations):
        """Generate an HTML report from the recommendations."""
        # Calculate total estimated savings
        total_savings = 0.0
        for rec in recommendations:
            savings_str = rec.get('EstimatedMonthlySavings', '$0.00')
            if isinstance(savings_str, str) and savings_str.startswith('$'):
                total_savings += float(savings_str[1:])
        
        # Group recommendations by resource type
        ec2_recs = [r for r in recommendations if r['ResourceType'] == 'EC2 Instance']
        rds_recs = [r for r in recommendations if r['ResourceType'] == 'RDS Instance']
        dynamodb_recs = [r for r in recommendations if r['ResourceType'] == 'DynamoDB Table']
        elasticache_recs = [r for r in recommendations if r['ResourceType'] == 'ElastiCache Cluster']
        
        # Generate HTML content
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AWS Resource Rightsizing Recommendations</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2 {{ color: #0066cc; }}
                .summary {{ background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .savings {{ font-size: 24px; font-weight: bold; color: #009900; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #0066cc; color: white; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
                .footer {{ margin-top: 30px; font-size: 12px; color: #666; text-align: center; }}
            </style>
        </head>
        <body>
            <h1>AWS Resource Rightsizing Recommendations</h1>
            <div class="summary">
                <p>Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Total recommendations: {len(recommendations)}</p>
                <p>Total estimated monthly savings: <span class="savings">${total_savings:.2f}</span></p>
            </div>
        """
        
        # Add EC2 recommendations
        if ec2_recs:
            html += """
            <h2>EC2 Instance Recommendations</h2>
            <table>
                <tr>
                    <th>Instance ID</th>
                    <th>Name</th>
                    <th>Current Type</th>
                    <th>Recommended Type</th>
                    <th>Avg CPU</th>
                    <th>Max CPU</th>
                    <th>Est. Monthly Savings</th>
                </tr>
            """
            
            for rec in ec2_recs:
                html += f"""
                <tr>
                    <td>{rec['ResourceId']}</td>
                    <td>{rec['ResourceName']}</td>
                    <td>{rec['CurrentConfiguration']}</td>
                    <td>{rec['RecommendedConfiguration']}</td>
                    <td>{rec['AverageCPUUtilization']}</td>
                    <td>{rec['MaxCPUUtilization']}</td>
                    <td>{rec['EstimatedMonthlySavings']}</td>
                </tr>
                """
            
            html += "</table>"
        
        # Add RDS recommendations
        if rds_recs:
            html += """
            <h2>RDS Instance Recommendations</h2>
            <table>
                <tr>
                    <th>Instance ID</th>
                    <th>Engine</th>
                    <th>Current Class</th>
                    <th>Recommended Class</th>
                    <th>Avg CPU</th>
                    <th>Est. Monthly Savings</th>
                </tr>
            """
            
            for rec in rds_recs:
                html += f"""
                <tr>
                    <td>{rec['ResourceId']}</td>
                    <td>{rec['Engine']}</td>
                    <td>{rec['CurrentConfiguration']}</td>
                    <td>{rec['RecommendedConfiguration']}</td>
                    <td>{rec['AverageCPUUtilization']}</td>
                    <td>{rec['EstimatedMonthlySavings']}</td>
                </tr>
                """
            
            html += "</table>"
        
        # Add DynamoDB recommendations
        if dynamodb_recs:
            html += """
            <h2>DynamoDB Table Recommendations</h2>
            <table>
                <tr>
                    <th>Table Name</th>
                    <th>Current Read</th>
                    <th>Current Write</th>
                    <th>Recommended Read</th>
                    <th>Recommended Write</th>
                    <th>Est. Monthly Savings</th>
                    <th>Consider On-Demand</th>
                </tr>
            """
            
            for rec in dynamodb_recs:
                html += f"""
                <tr>
                    <td>{rec['ResourceName']}</td>
                    <td>{rec['CurrentReadCapacity']}</td>
                    <td>{rec['CurrentWriteCapacity']}</td>
                    <td>{rec['RecommendedReadCapacity']}</td>
                    <td>{rec['RecommendedWriteCapacity']}</td>
                    <td>{rec['EstimatedMonthlySavings']}</td>
                    <td>{rec['ConsiderOnDemand']}</td>
                </tr>
                """
            
            html += "</table>"
        
        # Add ElastiCache recommendations
        if elasticache_recs:
            html += """
            <h2>ElastiCache Cluster Recommendations</h2>
            <table>
                <tr>
                    <th>Cluster ID</th>
                    <th>Engine</th>
                    <th>Current Type</th>
                    <th>Recommended Type</th>
                    <th>Avg CPU</th>
                    <th>Avg Memory</th>
                    <th>Est. Monthly Savings</th>
                </tr>
            """
            
            for rec in elasticache_recs:
                html += f"""
                <tr>
                    <td>{rec['ResourceId']}</td>
                    <td>{rec['Engine']}</td>
                    <td>{rec['CurrentConfiguration']}</td>
                    <td>{rec['RecommendedConfiguration']}</td>
                    <td>{rec['AverageCPUUtilization']}</td>
                    <td>{rec['AverageMemoryUtilization']}</td>
                    <td>{rec['EstimatedMonthlySavings']}</td>
                </tr>
                """
            
            html += "</table>"
        
        # Add footer
        html += """
            <div class="footer">
                <p>Generated by AWS Resource Rightsizer - Authored by V Vier</p>
            </div>
        </body>
        </html>
        """
        
        return html

def main():
    parser = argparse.ArgumentParser(description='AWS Resource Rightsizer')
    parser.add_argument('--region', help='AWS region')
    parser.add_argument('--profile', help='AWS profile')
    parser.add_argument('--service', choices=['ec2', 'rds', 'dynamodb', 'elasticache', 'all'], default='all', help='AWS service to analyze')
    parser.add_argument('--days', type=int, default=14, help='Number of days to analyze')
    parser.add_argument('--threshold', type=int, default=30, help='Utilization threshold percentage')
    parser.add_argument('--format', choices=['table', 'json', 'csv'], default='table', help='Output format')
    parser.add_argument('--export', help='Export results to a file')
    parser.add_argument('--export-format', choices=['json', 'csv', 'html'], default='json', help='Export file format')
    
    args = parser.parse_args()
    
    rightsizer = ResourceRightsizer(region=args.region, profile=args.profile)
    
    recommendations = []
    
    if args.service == 'ec2' or args.service == 'all':
        ec2_recommendations = rightsizer.analyze_ec2_instances(args.days, args.threshold)
        recommendations.extend(ec2_recommendations)
    
    if args.service == 'rds' or args.service == 'all':
        rds_recommendations = rightsizer.analyze_rds_instances(args.days, args.threshold)
        recommendations.extend(rds_recommendations)
    
    if args.service == 'dynamodb' or args.service == 'all':
        dynamodb_recommendations = rightsizer.analyze_dynamodb_tables(args.days)
        recommendations.extend(dynamodb_recommendations)
    
    if args.service == 'elasticache' or args.service == 'all':
        elasticache_recommendations = rightsizer.analyze_elasticache_clusters(args.days, args.threshold)
        recommendations.extend(elasticache_recommendations)
    
    rightsizer.print_results(recommendations, format=args.format)
    
    if args.export:
        rightsizer.export_results(recommendations, args.export, format=args.export_format)

if __name__ == '__main__':
    main()
