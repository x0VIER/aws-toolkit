#!/usr/bin/env python3
"""
Public Resource Finder

This script identifies AWS resources that are publicly accessible or have public access enabled,
which could pose security risks if not properly secured.

Author: V Vier
"""

import argparse
import boto3
import json
import sys
import csv
from datetime import datetime
from botocore.exceptions import ClientError
from tabulate import tabulate

class PublicResourceFinder:
    def __init__(self, region=None, profile=None):
        """Initialize the Public Resource Finder with optional region and profile."""
        session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
        self.ec2 = session.client('ec2')
        self.s3 = session.client('s3')
        self.rds = session.client('rds')
        self.elb = session.client('elbv2')
        self.lambda_client = session.client('lambda')
        self.apigateway = session.client('apigateway')
        self.region = region or session.region_name
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        
    def find_public_ec2_instances(self):
        """Find EC2 instances with public IP addresses."""
        public_instances = []
        
        try:
            # Get all running instances
            response = self.ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    # Check if instance has a public IP
                    if 'PublicIpAddress' in instance:
                        # Get instance name from tags
                        instance_name = "Unnamed"
                        if 'Tags' in instance:
                            for tag in instance['Tags']:
                                if tag['Key'] == 'Name':
                                    instance_name = tag['Value']
                                    break
                        
                        # Get security groups
                        security_groups = []
                        for sg in instance['SecurityGroups']:
                            security_groups.append(sg['GroupId'])
                        
                        public_instances.append({
                            'ResourceId': instance['InstanceId'],
                            'ResourceType': 'EC2 Instance',
                            'ResourceName': instance_name,
                            'PublicEndpoint': instance['PublicIpAddress'],
                            'Region': self.region,
                            'SecurityGroups': security_groups,
                            'LaunchTime': instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
                        })
            
            return public_instances
        except ClientError as e:
            print(f"Error finding public EC2 instances: {e}")
            return []
    
    def find_public_security_groups(self):
        """Find security groups with rules allowing public access."""
        public_security_groups = []
        
        try:
            # Get all security groups
            response = self.ec2.describe_security_groups()
            
            for sg in response['SecurityGroups']:
                has_public_ingress = False
                public_ports = []
                
                # Check ingress rules
                for rule in sg['IpPermissions']:
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            has_public_ingress = True
                            
                            # Determine port range
                            if 'FromPort' in rule and 'ToPort' in rule:
                                if rule['FromPort'] == rule['ToPort']:
                                    public_ports.append(str(rule['FromPort']))
                                else:
                                    public_ports.append(f"{rule['FromPort']}-{rule['ToPort']}")
                            else:
                                public_ports.append('All')
                
                if has_public_ingress:
                    # Get security group name
                    sg_name = sg['GroupName']
                    
                    public_security_groups.append({
                        'ResourceId': sg['GroupId'],
                        'ResourceType': 'Security Group',
                        'ResourceName': sg_name,
                        'PublicEndpoint': '0.0.0.0/0',
                        'Region': self.region,
                        'OpenPorts': ', '.join(public_ports),
                        'Description': sg['Description']
                    })
            
            return public_security_groups
        except ClientError as e:
            print(f"Error finding public security groups: {e}")
            return []
    
    def find_public_s3_buckets(self):
        """Find S3 buckets with public access enabled."""
        public_buckets = []
        
        try:
            # Get all S3 buckets
            response = self.s3.list_buckets()
            
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                
                try:
                    # Check bucket policy
                    try:
                        policy = self.s3.get_bucket_policy(Bucket=bucket_name)
                        policy_json = json.loads(policy['Policy'])
                        
                        # Check if policy allows public access
                        has_public_policy = False
                        for statement in policy_json.get('Statement', []):
                            principal = statement.get('Principal', {})
                            if principal == '*' or principal.get('AWS') == '*':
                                has_public_policy = True
                                break
                    except ClientError:
                        has_public_policy = False
                    
                    # Check bucket ACL
                    try:
                        acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                        has_public_acl = False
                        
                        for grant in acl.get('Grants', []):
                            grantee = grant.get('Grantee', {})
                            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                                has_public_acl = True
                                break
                    except ClientError:
                        has_public_acl = False
                    
                    # Check bucket public access block
                    try:
                        public_access_block = self.s3.get_public_access_block(Bucket=bucket_name)
                        block_config = public_access_block['PublicAccessBlockConfiguration']
                        
                        # If any of these are False, public access might be allowed
                        public_access_blocked = (
                            block_config.get('BlockPublicAcls', False) and
                            block_config.get('IgnorePublicAcls', False) and
                            block_config.get('BlockPublicPolicy', False) and
                            block_config.get('RestrictPublicBuckets', False)
                        )
                    except ClientError:
                        # If no public access block is set, assume public access is allowed
                        public_access_blocked = False
                    
                    if has_public_policy or has_public_acl or not public_access_blocked:
                        # Check if bucket has website configuration
                        try:
                            website = self.s3.get_bucket_website(Bucket=bucket_name)
                            has_website = True
                            website_endpoint = f"http://{bucket_name}.s3-website-{self.region}.amazonaws.com"
                        except ClientError:
                            has_website = False
                            website_endpoint = None
                        
                        public_buckets.append({
                            'ResourceId': bucket_name,
                            'ResourceType': 'S3 Bucket',
                            'ResourceName': bucket_name,
                            'PublicEndpoint': website_endpoint if has_website else 'N/A',
                            'Region': self.region,
                            'PublicPolicy': 'Yes' if has_public_policy else 'No',
                            'PublicACL': 'Yes' if has_public_acl else 'No',
                            'PublicAccessBlocked': 'No' if not public_access_blocked else 'Yes',
                            'WebsiteEnabled': 'Yes' if has_website else 'No'
                        })
                
                except ClientError as e:
                    # Skip buckets that we don't have permission to check
                    if 'AccessDenied' not in str(e):
                        print(f"Error checking bucket {bucket_name}: {e}")
            
            return public_buckets
        except ClientError as e:
            print(f"Error finding public S3 buckets: {e}")
            return []
    
    def find_public_rds_instances(self):
        """Find RDS instances that are publicly accessible."""
        public_rds = []
        
        try:
            # Get all RDS instances
            response = self.rds.describe_db_instances()
            
            for db in response['DBInstances']:
                if db.get('PubliclyAccessible', False):
                    public_rds.append({
                        'ResourceId': db['DBInstanceIdentifier'],
                        'ResourceType': 'RDS Instance',
                        'ResourceName': db['DBInstanceIdentifier'],
                        'PublicEndpoint': db.get('Endpoint', {}).get('Address', 'N/A'),
                        'Region': self.region,
                        'Engine': db['Engine'],
                        'EngineVersion': db['EngineVersion'],
                        'StorageEncrypted': 'Yes' if db.get('StorageEncrypted', False) else 'No'
                    })
            
            return public_rds
        except ClientError as e:
            print(f"Error finding public RDS instances: {e}")
            return []
    
    def find_public_load_balancers(self):
        """Find load balancers that are internet-facing."""
        public_lbs = []
        
        try:
            # Get all load balancers
            response = self.elb.describe_load_balancers()
            
            for lb in response['LoadBalancers']:
                if lb['Scheme'] == 'internet-facing':
                    public_lbs.append({
                        'ResourceId': lb['LoadBalancerArn'].split('/')[-1],
                        'ResourceType': f"{lb['Type']} Load Balancer",
                        'ResourceName': lb['LoadBalancerName'],
                        'PublicEndpoint': lb['DNSName'],
                        'Region': self.region,
                        'VpcId': lb['VpcId'],
                        'State': lb['State']['Code'],
                        'CreatedTime': lb['CreatedTime'].strftime('%Y-%m-%d %H:%M:%S')
                    })
            
            return public_lbs
        except ClientError as e:
            print(f"Error finding public load balancers: {e}")
            return []
    
    def find_public_lambda_functions(self):
        """Find Lambda functions with public access."""
        public_lambdas = []
        
        try:
            # Get all Lambda functions
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
            
            for function in functions:
                # Check if function has a public policy
                try:
                    policy_response = self.lambda_client.get_policy(FunctionName=function['FunctionName'])
                    policy = json.loads(policy_response['Policy'])
                    
                    # Check if policy allows public access
                    has_public_policy = False
                    for statement in policy.get('Statement', []):
                        principal = statement.get('Principal', {})
                        if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                            has_public_policy = True
                            break
                    
                    if has_public_policy:
                        public_lambdas.append({
                            'ResourceId': function['FunctionArn'],
                            'ResourceType': 'Lambda Function',
                            'ResourceName': function['FunctionName'],
                            'PublicEndpoint': 'API Gateway or Function URL',
                            'Region': self.region,
                            'Runtime': function['Runtime'],
                            'LastModified': function['LastModified']
                        })
                
                except ClientError as e:
                    # Skip functions without a policy
                    if 'ResourceNotFoundException' not in str(e):
                        print(f"Error checking Lambda function {function['FunctionName']}: {e}")
            
            return public_lambdas
        except ClientError as e:
            print(f"Error finding public Lambda functions: {e}")
            return []
    
    def find_public_api_gateways(self):
        """Find API Gateway APIs that are publicly accessible."""
        public_apis = []
        
        try:
            # Get all REST APIs
            rest_apis = self.apigateway.get_rest_apis()
            
            for api in rest_apis['items']:
                # Check if API has stages
                stages = self.apigateway.get_stages(restApiId=api['id'])
                
                for stage in stages['item']:
                    # Check if stage has API key required
                    api_key_required = False
                    
                    try:
                        resources = self.apigateway.get_resources(restApiId=api['id'])
                        
                        for resource in resources['items']:
                            for method_type, method in resource.get('resourceMethods', {}).items():
                                method_detail = self.apigateway.get_method(
                                    restApiId=api['id'],
                                    resourceId=resource['id'],
                                    httpMethod=method_type
                                )
                                
                                if method_detail.get('apiKeyRequired', False):
                                    api_key_required = True
                                    break
                            
                            if api_key_required:
                                break
                    
                    except ClientError:
                        pass
                    
                    # If API key is not required, consider it public
                    if not api_key_required:
                        endpoint = f"https://{api['id']}.execute-api.{self.region}.amazonaws.com/{stage['stageName']}"
                        
                        public_apis.append({
                            'ResourceId': api['id'],
                            'ResourceType': 'API Gateway REST API',
                            'ResourceName': api['name'],
                            'PublicEndpoint': endpoint,
                            'Region': self.region,
                            'Stage': stage['stageName'],
                            'ApiKeyRequired': 'No',
                            'Description': api.get('description', 'N/A')
                        })
            
            # Get all HTTP APIs
            try:
                http_apis = self.apigateway.get_apis()
                
                for api in http_apis.get('Items', []):
                    # HTTP APIs are public by default unless they have authorization
                    has_authorizer = False
                    
                    try:
                        routes = self.apigateway.get_routes(ApiId=api['ApiId'])
                        
                        for route in routes.get('Items', []):
                            if route.get('AuthorizationType') not in [None, 'NONE']:
                                has_authorizer = True
                                break
                    
                    except ClientError:
                        pass
                    
                    if not has_authorizer:
                        endpoint = f"https://{api['ApiId']}.execute-api.{self.region}.amazonaws.com"
                        
                        public_apis.append({
                            'ResourceId': api['ApiId'],
                            'ResourceType': 'API Gateway HTTP API',
                            'ResourceName': api['Name'],
                            'PublicEndpoint': endpoint,
                            'Region': self.region,
                            'AuthorizationType': 'None',
                            'Description': api.get('Description', 'N/A')
                        })
            
            except ClientError:
                # HTTP API might not be available in all regions
                pass
            
            return public_apis
        except ClientError as e:
            print(f"Error finding public API Gateway APIs: {e}")
            return []
    
    def find_all_public_resources(self):
        """Find all public resources across different services."""
        all_resources = []
        
        print("Searching for public EC2 instances...")
        ec2_instances = self.find_public_ec2_instances()
        all_resources.extend(ec2_instances)
        print(f"Found {len(ec2_instances)} public EC2 instances.")
        
        print("Searching for public security groups...")
        security_groups = self.find_public_security_groups()
        all_resources.extend(security_groups)
        print(f"Found {len(security_groups)} public security groups.")
        
        print("Searching for public S3 buckets...")
        s3_buckets = self.find_public_s3_buckets()
        all_resources.extend(s3_buckets)
        print(f"Found {len(s3_buckets)} public S3 buckets.")
        
        print("Searching for public RDS instances...")
        rds_instances = self.find_public_rds_instances()
        all_resources.extend(rds_instances)
        print(f"Found {len(rds_instances)} public RDS instances.")
        
        print("Searching for public load balancers...")
        load_balancers = self.find_public_load_balancers()
        all_resources.extend(load_balancers)
        print(f"Found {len(load_balancers)} public load balancers.")
        
        print("Searching for public Lambda functions...")
        lambda_functions = self.find_public_lambda_functions()
        all_resources.extend(lambda_functions)
        print(f"Found {len(lambda_functions)} public Lambda functions.")
        
        print("Searching for public API Gateway APIs...")
        api_gateways = self.find_public_api_gateways()
        all_resources.extend(api_gateways)
        print(f"Found {len(api_gateways)} public API Gateway APIs.")
        
        return all_resources
    
    def print_results(self, resources, format='table'):
        """Print the results in the specified format."""
        if not resources:
            print("No public resources found.")
            return
        
        if format == 'table':
            # Prepare table data
            headers = ['Resource Type', 'Resource ID', 'Resource Name', 'Public Endpoint', 'Region']
            table_data = []
            
            for resource in resources:
                table_data.append([
                    resource['ResourceType'],
                    resource['ResourceId'],
                    resource['ResourceName'],
                    resource['PublicEndpoint'],
                    resource['Region']
                ])
            
            print(tabulate(table_data, headers=headers, tablefmt='grid'))
            
        elif format == 'json':
            print(json.dumps(resources, indent=2, default=str))
            
        elif format == 'csv':
            # Get all possible keys
            all_keys = set()
            for resource in resources:
                all_keys.update(resource.keys())
            
            # Print CSV to stdout
            writer = csv.DictWriter(sys.stdout, fieldnames=sorted(all_keys))
            writer.writeheader()
            for resource in resources:
                writer.writerow(resource)
    
    def export_results(self, resources, filename, format='json'):
        """Export the results to a file in the specified format."""
        if not resources:
            print("No public resources found to export.")
            return
        
        try:
            if format == 'json':
                with open(filename, 'w') as f:
                    json.dump(resources, f, indent=2, default=str)
                    
            elif format == 'csv':
                # Get all possible keys
                all_keys = set()
                for resource in resources:
                    all_keys.update(resource.keys())
                
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=sorted(all_keys))
                    writer.writeheader()
                    for resource in resources:
                        writer.writerow(resource)
            
            print(f"Results exported to {filename}")
            
        except Exception as e:
            print(f"Error exporting results: {e}")

def main():
    parser = argparse.ArgumentParser(description='Find publicly accessible AWS resources')
    parser.add_argument('--region', help='AWS region')
    parser.add_argument('--profile', help='AWS profile')
    parser.add_argument('--service', choices=['ec2', 's3', 'rds', 'elb', 'lambda', 'apigateway', 'all'], default='all', help='AWS service to check')
    parser.add_argument('--format', choices=['table', 'json', 'csv'], default='table', help='Output format')
    parser.add_argument('--export', help='Export results to a file')
    parser.add_argument('--export-format', choices=['json', 'csv'], default='json', help='Export file format')
    
    args = parser.parse_args()
    
    finder = PublicResourceFinder(region=args.region, profile=args.profile)
    
    resources = []
    
    if args.service == 'ec2' or args.service == 'all':
        print("Searching for public EC2 instances...")
        ec2_instances = finder.find_public_ec2_instances()
        resources.extend(ec2_instances)
        print(f"Found {len(ec2_instances)} public EC2 instances.")
        
        print("Searching for public security groups...")
        security_groups = finder.find_public_security_groups()
        resources.extend(security_groups)
        print(f"Found {len(security_groups)} public security groups.")
    
    if args.service == 's3' or args.service == 'all':
        print("Searching for public S3 buckets...")
        s3_buckets = finder.find_public_s3_buckets()
        resources.extend(s3_buckets)
        print(f"Found {len(s3_buckets)} public S3 buckets.")
    
    if args.service == 'rds' or args.service == 'all':
        print("Searching for public RDS instances...")
        rds_instances = finder.find_public_rds_instances()
        resources.extend(rds_instances)
        print(f"Found {len(rds_instances)} public RDS instances.")
    
    if args.service == 'elb' or args.service == 'all':
        print("Searching for public load balancers...")
        load_balancers = finder.find_public_load_balancers()
        resources.extend(load_balancers)
        print(f"Found {len(load_balancers)} public load balancers.")
    
    if args.service == 'lambda' or args.service == 'all':
        print("Searching for public Lambda functions...")
        lambda_functions = finder.find_public_lambda_functions()
        resources.extend(lambda_functions)
        print(f"Found {len(lambda_functions)} public Lambda functions.")
    
    if args.service == 'apigateway' or args.service == 'all':
        print("Searching for public API Gateway APIs...")
        api_gateways = finder.find_public_api_gateways()
        resources.extend(api_gateways)
        print(f"Found {len(api_gateways)} public API Gateway APIs.")
    
    print(f"\nTotal public resources found: {len(resources)}")
    
    finder.print_results(resources, format=args.format)
    
    if args.export:
        finder.export_results(resources, args.export, format=args.export_format)

if __name__ == '__main__':
    main()
