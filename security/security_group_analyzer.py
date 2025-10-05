#!/usr/bin/env python3
"""
Security Group Analyzer

A comprehensive tool for analyzing AWS security groups to identify
overly permissive rules, unused rules, and compliance violations.

Author: V Vier
"""

import argparse
import sys
import json
import ipaddress
import boto3
from botocore.exceptions import ClientError
from tabulate import tabulate
from colorama import init, Fore, Style

# Initialize colorama
init()

class SecurityGroupAnalyzer:
    """Analyzes security groups across AWS regions."""
    
    def __init__(self, region=None, profile=None):
        """Initialize the security group analyzer.
        
        Args:
            region (str): AWS region name (e.g., 'us-east-1')
            profile (str): AWS profile name to use
        """
        self.region = region
        self.profile = profile
        self.session = self._create_session()
        self.ec2_client = self.session.client('ec2', region_name=self.region)
        self.ec2_resource = self.session.resource('ec2', region_name=self.region)
    
    def _create_session(self):
        """Create a boto3 session with the specified profile if provided."""
        if self.profile:
            return boto3.Session(profile_name=self.profile, region_name=self.region)
        return boto3.Session(region_name=self.region)
    
    def get_all_security_groups(self):
        """Get all security groups in the region.
        
        Returns:
            list: List of security group dictionaries
        """
        try:
            security_groups = []
            paginator = self.ec2_client.get_paginator('describe_security_groups')
            
            for page in paginator.paginate():
                security_groups.extend(page['SecurityGroups'])
            
            return security_groups
        except ClientError as e:
            print(f"{Fore.RED}Error getting security groups: {e}{Style.RESET_ALL}")
            return []
    
    def get_security_group_usage(self, security_group_id):
        """Get usage information for a security group.
        
        Args:
            security_group_id (str): ID of the security group
            
        Returns:
            dict: Dictionary containing usage information
        """
        try:
            usage = {
                'EC2Instances': [],
                'NetworkInterfaces': [],
                'RDSInstances': [],
                'ElasticLoadBalancers': [],
                'ElastiCacheClusters': [],
                'RedshiftClusters': [],
                'LambdaFunctions': []
            }
            
            # Check EC2 instances
            instances = list(self.ec2_resource.instances.all())
            for instance in instances:
                for sg in instance.security_groups:
                    if sg['GroupId'] == security_group_id:
                        usage['EC2Instances'].append({
                            'InstanceId': instance.id,
                            'Name': next((tag['Value'] for tag in instance.tags or [] if tag['Key'] == 'Name'), 'N/A')
                        })
            
            # Check network interfaces
            network_interfaces = list(self.ec2_resource.network_interfaces.all())
            for ni in network_interfaces:
                for sg in ni.groups:
                    if sg['GroupId'] == security_group_id:
                        usage['NetworkInterfaces'].append({
                            'NetworkInterfaceId': ni.id,
                            'Description': ni.description
                        })
            
            # Check RDS instances
            try:
                rds_client = self.session.client('rds', region_name=self.region)
                rds_instances = rds_client.describe_db_instances()
                
                for instance in rds_instances['DBInstances']:
                    for sg in instance.get('VpcSecurityGroups', []):
                        if sg['VpcSecurityGroupId'] == security_group_id:
                            usage['RDSInstances'].append({
                                'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                                'Engine': instance['Engine']
                            })
            except ClientError:
                pass
            
            # Check Elastic Load Balancers
            try:
                elb_client = self.session.client('elb', region_name=self.region)
                load_balancers = elb_client.describe_load_balancers()
                
                for lb in load_balancers['LoadBalancerDescriptions']:
                    if security_group_id in lb.get('SecurityGroups', []):
                        usage['ElasticLoadBalancers'].append({
                            'LoadBalancerName': lb['LoadBalancerName'],
                            'Type': 'Classic'
                        })
            except ClientError:
                pass
            
            # Check Application and Network Load Balancers
            try:
                elbv2_client = self.session.client('elbv2', region_name=self.region)
                load_balancers = elbv2_client.describe_load_balancers()
                
                for lb in load_balancers['LoadBalancers']:
                    if security_group_id in lb.get('SecurityGroups', []):
                        usage['ElasticLoadBalancers'].append({
                            'LoadBalancerName': lb['LoadBalancerName'],
                            'Type': lb['Type']
                        })
            except ClientError:
                pass
            
            # Check ElastiCache clusters
            try:
                elasticache_client = self.session.client('elasticache', region_name=self.region)
                cache_clusters = elasticache_client.describe_cache_clusters()
                
                for cluster in cache_clusters['CacheClusters']:
                    for sg in cluster.get('SecurityGroups', []):
                        if sg['SecurityGroupId'] == security_group_id:
                            usage['ElastiCacheClusters'].append({
                                'CacheClusterId': cluster['CacheClusterId'],
                                'Engine': cluster['Engine']
                            })
            except ClientError:
                pass
            
            # Check Redshift clusters
            try:
                redshift_client = self.session.client('redshift', region_name=self.region)
                clusters = redshift_client.describe_clusters()
                
                for cluster in clusters['Clusters']:
                    for sg in cluster.get('VpcSecurityGroups', []):
                        if sg['VpcSecurityGroupId'] == security_group_id:
                            usage['RedshiftClusters'].append({
                                'ClusterIdentifier': cluster['ClusterIdentifier'],
                                'NodeType': cluster['NodeType']
                            })
            except ClientError:
                pass
            
            # Check Lambda functions
            try:
                lambda_client = self.session.client('lambda', region_name=self.region)
                functions = lambda_client.list_functions()
                
                for function in functions['Functions']:
                    if 'VpcConfig' in function and 'SecurityGroupIds' in function['VpcConfig']:
                        if security_group_id in function['VpcConfig']['SecurityGroupIds']:
                            usage['LambdaFunctions'].append({
                                'FunctionName': function['FunctionName'],
                                'Runtime': function['Runtime']
                            })
            except ClientError:
                pass
            
            return usage
        except ClientError as e:
            print(f"{Fore.RED}Error getting usage for security group {security_group_id}: {e}{Style.RESET_ALL}")
            return None
    
    def analyze_security_group(self, security_group):
        """Analyze a security group for potential issues.
        
        Args:
            security_group (dict): Security group dictionary
            
        Returns:
            dict: Dictionary containing analysis results
        """
        analysis = {
            'GroupId': security_group['GroupId'],
            'GroupName': security_group['GroupName'],
            'VpcId': security_group.get('VpcId', 'N/A'),
            'Description': security_group['Description'],
            'PermissiveRules': [],
            'UnusedPorts': [],
            'RedundantRules': [],
            'ComplianceIssues': []
        }
        
        # Check for permissive inbound rules
        for rule in security_group.get('IpPermissions', []):
            # Get port range
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 0)
            ip_protocol = rule.get('IpProtocol', '-1')
            
            # Check IP ranges
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                
                # Check for overly permissive rules
                if cidr == '0.0.0.0/0':
                    # All traffic from anywhere
                    if ip_protocol == '-1':
                        analysis['PermissiveRules'].append({
                            'Type': 'Inbound',
                            'Protocol': 'All',
                            'Ports': 'All',
                            'Source': cidr,
                            'Severity': 'High'
                        })
                    # Common sensitive ports
                    elif ip_protocol == 'tcp':
                        sensitive_ports = {
                            22: 'SSH',
                            3389: 'RDP',
                            1433: 'MSSQL',
                            3306: 'MySQL',
                            5432: 'PostgreSQL',
                            27017: 'MongoDB',
                            6379: 'Redis',
                            9200: 'Elasticsearch',
                            8080: 'HTTP Alt',
                            8443: 'HTTPS Alt'
                        }
                        
                        for port in range(from_port, to_port + 1):
                            if port in sensitive_ports:
                                analysis['PermissiveRules'].append({
                                    'Type': 'Inbound',
                                    'Protocol': 'TCP',
                                    'Ports': str(port),
                                    'Service': sensitive_ports[port],
                                    'Source': cidr,
                                    'Severity': 'High'
                                })
                        
                        # Wide port ranges
                        if to_port - from_port > 100:
                            analysis['PermissiveRules'].append({
                                'Type': 'Inbound',
                                'Protocol': 'TCP',
                                'Ports': f"{from_port}-{to_port}",
                                'Source': cidr,
                                'Severity': 'Medium'
                            })
                elif cidr.endswith('/8') or cidr.endswith('/0'):
                    # Large CIDR blocks
                    analysis['PermissiveRules'].append({
                        'Type': 'Inbound',
                        'Protocol': ip_protocol if ip_protocol != '-1' else 'All',
                        'Ports': f"{from_port}-{to_port}" if from_port is not None else 'All',
                        'Source': cidr,
                        'Severity': 'Medium'
                    })
            
            # Check IPv6 ranges
            for ip_range in rule.get('Ipv6Ranges', []):
                cidr = ip_range.get('CidrIpv6', '')
                
                # Check for overly permissive rules
                if cidr == '::/0':
                    # All traffic from anywhere (IPv6)
                    if ip_protocol == '-1':
                        analysis['PermissiveRules'].append({
                            'Type': 'Inbound',
                            'Protocol': 'All',
                            'Ports': 'All',
                            'Source': cidr,
                            'Severity': 'High'
                        })
                    # Common sensitive ports
                    elif ip_protocol == 'tcp':
                        sensitive_ports = {
                            22: 'SSH',
                            3389: 'RDP',
                            1433: 'MSSQL',
                            3306: 'MySQL',
                            5432: 'PostgreSQL',
                            27017: 'MongoDB',
                            6379: 'Redis',
                            9200: 'Elasticsearch',
                            8080: 'HTTP Alt',
                            8443: 'HTTPS Alt'
                        }
                        
                        for port in range(from_port, to_port + 1):
                            if port in sensitive_ports:
                                analysis['PermissiveRules'].append({
                                    'Type': 'Inbound',
                                    'Protocol': 'TCP',
                                    'Ports': str(port),
                                    'Service': sensitive_ports[port],
                                    'Source': cidr,
                                    'Severity': 'High'
                                })
        
        # Check for permissive outbound rules
        for rule in security_group.get('IpPermissionsEgress', []):
            # Get port range
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 0)
            ip_protocol = rule.get('IpProtocol', '-1')
            
            # Check IP ranges
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                
                # Check for overly permissive rules
                if cidr == '0.0.0.0/0' and ip_protocol == '-1':
                    analysis['PermissiveRules'].append({
                        'Type': 'Outbound',
                        'Protocol': 'All',
                        'Ports': 'All',
                        'Destination': cidr,
                        'Severity': 'Low'  # Less severe for outbound
                    })
        
        # Check for compliance issues
        # CIS AWS Foundations Benchmark - Security Group checks
        
        # Check for unrestricted inbound SSH access
        for rule in security_group.get('IpPermissions', []):
            if rule.get('IpProtocol') == 'tcp' and rule.get('FromPort') <= 22 and rule.get('ToPort') >= 22:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        analysis['ComplianceIssues'].append({
                            'Standard': 'CIS AWS Foundations',
                            'Control': '4.1',
                            'Description': 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22',
                            'Severity': 'High'
                        })
        
        # Check for unrestricted inbound RDP access
        for rule in security_group.get('IpPermissions', []):
            if rule.get('IpProtocol') == 'tcp' and rule.get('FromPort') <= 3389 and rule.get('ToPort') >= 3389:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        analysis['ComplianceIssues'].append({
                            'Standard': 'CIS AWS Foundations',
                            'Control': '4.2',
                            'Description': 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389',
                            'Severity': 'High'
                        })
        
        # Get security group usage
        usage = self.get_security_group_usage(security_group['GroupId'])
        
        # Check for unused ports
        if not usage['EC2Instances'] and not usage['NetworkInterfaces'] and not usage['RDSInstances'] and not usage['ElasticLoadBalancers'] and not usage['ElastiCacheClusters'] and not usage['RedshiftClusters'] and not usage['LambdaFunctions']:
            # Security group is not used by any resource
            for rule in security_group.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 0)
                ip_protocol = rule.get('IpProtocol', '-1')
                
                if from_port is not None and to_port is not None:
                    analysis['UnusedPorts'].append({
                        'Protocol': ip_protocol if ip_protocol != '-1' else 'All',
                        'Ports': f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                        'Reason': 'Security group not attached to any resource'
                    })
        
        # Check for redundant rules
        inbound_rules = {}
        for rule in security_group.get('IpPermissions', []):
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 0)
            ip_protocol = rule.get('IpProtocol', '-1')
            
            # Create a key for the rule
            rule_key = f"{ip_protocol}:{from_port}-{to_port}"
            
            # Check for duplicate CIDR blocks
            cidr_blocks = set()
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                if cidr in cidr_blocks:
                    analysis['RedundantRules'].append({
                        'Type': 'Inbound',
                        'Protocol': ip_protocol if ip_protocol != '-1' else 'All',
                        'Ports': f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                        'Source': cidr,
                        'Reason': 'Duplicate CIDR block'
                    })
                cidr_blocks.add(cidr)
            
            # Check for overlapping CIDR blocks
            cidr_list = [ip_range.get('CidrIp', '') for ip_range in rule.get('IpRanges', [])]
            for i, cidr1 in enumerate(cidr_list):
                try:
                    network1 = ipaddress.ip_network(cidr1)
                    for j, cidr2 in enumerate(cidr_list):
                        if i != j:
                            try:
                                network2 = ipaddress.ip_network(cidr2)
                                if network1.overlaps(network2):
                                    analysis['RedundantRules'].append({
                                        'Type': 'Inbound',
                                        'Protocol': ip_protocol if ip_protocol != '-1' else 'All',
                                        'Ports': f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                                        'Source1': cidr1,
                                        'Source2': cidr2,
                                        'Reason': 'Overlapping CIDR blocks'
                                    })
                            except ValueError:
                                pass
                except ValueError:
                    pass
        
        return analysis
    
    def display_security_group_analysis(self, analysis):
        """Display security group analysis results.
        
        Args:
            analysis (dict): Dictionary containing analysis results
        """
        print(f"\n{Fore.YELLOW}Security Group Analysis: {analysis['GroupName']} ({analysis['GroupId']}){Style.RESET_ALL}")
        print(f"VPC: {analysis['VpcId']}")
        print(f"Description: {analysis['Description']}")
        
        # Display permissive rules
        if analysis['PermissiveRules']:
            print(f"\n{Fore.RED}Permissive Rules:{Style.RESET_ALL}")
            headers = ["Type", "Protocol", "Ports", "Source/Destination", "Severity"]
            table_data = []
            
            for rule in analysis['PermissiveRules']:
                severity = rule['Severity']
                if severity == 'High':
                    severity = f"{Fore.RED}{severity}{Style.RESET_ALL}"
                elif severity == 'Medium':
                    severity = f"{Fore.YELLOW}{severity}{Style.RESET_ALL}"
                else:
                    severity = f"{Fore.GREEN}{severity}{Style.RESET_ALL}"
                
                source_dest = rule.get('Source', rule.get('Destination', 'N/A'))
                
                table_data.append([
                    rule['Type'],
                    rule['Protocol'],
                    rule['Ports'],
                    source_dest,
                    severity
                ])
            
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            print(f"\n{Fore.GREEN}No permissive rules found.{Style.RESET_ALL}")
        
        # Display unused ports
        if analysis['UnusedPorts']:
            print(f"\n{Fore.YELLOW}Unused Ports:{Style.RESET_ALL}")
            headers = ["Protocol", "Ports", "Reason"]
            table_data = []
            
            for port in analysis['UnusedPorts']:
                table_data.append([
                    port['Protocol'],
                    port['Ports'],
                    port['Reason']
                ])
            
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            print(f"\n{Fore.GREEN}No unused ports found.{Style.RESET_ALL}")
        
        # Display redundant rules
        if analysis['RedundantRules']:
            print(f"\n{Fore.YELLOW}Redundant Rules:{Style.RESET_ALL}")
            headers = ["Type", "Protocol", "Ports", "Source", "Reason"]
            table_data = []
            
            for rule in analysis['RedundantRules']:
                source = rule.get('Source', 'N/A')
                if 'Source1' in rule and 'Source2' in rule:
                    source = f"{rule['Source1']} overlaps {rule['Source2']}"
                
                table_data.append([
                    rule['Type'],
                    rule['Protocol'],
                    rule['Ports'],
                    source,
                    rule['Reason']
                ])
            
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            print(f"\n{Fore.GREEN}No redundant rules found.{Style.RESET_ALL}")
        
        # Display compliance issues
        if analysis['ComplianceIssues']:
            print(f"\n{Fore.RED}Compliance Issues:{Style.RESET_ALL}")
            headers = ["Standard", "Control", "Description", "Severity"]
            table_data = []
            
            for issue in analysis['ComplianceIssues']:
                severity = issue['Severity']
                if severity == 'High':
                    severity = f"{Fore.RED}{severity}{Style.RESET_ALL}"
                elif severity == 'Medium':
                    severity = f"{Fore.YELLOW}{severity}{Style.RESET_ALL}"
                else:
                    severity = f"{Fore.GREEN}{severity}{Style.RESET_ALL}"
                
                table_data.append([
                    issue['Standard'],
                    issue['Control'],
                    issue['Description'],
                    severity
                ])
            
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            print(f"\n{Fore.GREEN}No compliance issues found.{Style.RESET_ALL}")
    
    def generate_security_group_report(self, security_group_id=None, check_permissive=False, check_unused=False, check_redundant=False, check_compliance=False):
        """Generate a report for security groups.
        
        Args:
            security_group_id (str): ID of a specific security group to report on
            check_permissive (bool): Whether to only report security groups with permissive rules
            check_unused (bool): Whether to only report security groups with unused ports
            check_redundant (bool): Whether to only report security groups with redundant rules
            check_compliance (bool): Whether to only report security groups with compliance issues
            
        Returns:
            list: List of security group analysis results
        """
        try:
            analysis_results = []
            
            # Get all security groups or a specific security group
            if security_group_id:
                security_groups = self.ec2_client.describe_security_groups(GroupIds=[security_group_id])['SecurityGroups']
            else:
                security_groups = self.get_all_security_groups()
            
            # Process each security group
            for sg in security_groups:
                analysis = self.analyze_security_group(sg)
                
                # Filter based on checks
                if check_permissive and not analysis['PermissiveRules']:
                    continue
                if check_unused and not analysis['UnusedPorts']:
                    continue
                if check_redundant and not analysis['RedundantRules']:
                    continue
                if check_compliance and not analysis['ComplianceIssues']:
                    continue
                
                analysis_results.append(analysis)
            
            return analysis_results
        except ClientError as e:
            print(f"{Fore.RED}Error generating security group report: {e}{Style.RESET_ALL}")
            return []
    
    def export_report(self, analysis_results, output_format, output_file):
        """Export a report to a file.
        
        Args:
            analysis_results (list): List of security group analysis results
            output_format (str): Output format (json or csv)
            output_file (str): Output file path
            
        Returns:
            bool: True if export was successful, False otherwise
        """
        try:
            # Export to the specified format
            if output_format == 'json':
                with open(output_file, 'w') as f:
                    json.dump(analysis_results, f, indent=2)
            elif output_format == 'csv':
                if not analysis_results:
                    print(f"{Fore.YELLOW}No data to export.{Style.RESET_ALL}")
                    return False
                
                # Flatten the data for CSV export
                csv_data = []
                for analysis in analysis_results:
                    base_row = {
                        'GroupId': analysis['GroupId'],
                        'GroupName': analysis['GroupName'],
                        'VpcId': analysis['VpcId'],
                        'Description': analysis['Description']
                    }
                    
                    # Add permissive rules
                    if analysis['PermissiveRules']:
                        for rule in analysis['PermissiveRules']:
                            row = base_row.copy()
                            row['IssueType'] = 'Permissive Rule'
                            row['RuleType'] = rule['Type']
                            row['Protocol'] = rule['Protocol']
                            row['Ports'] = rule['Ports']
                            row['Source/Destination'] = rule.get('Source', rule.get('Destination', 'N/A'))
                            row['Severity'] = rule['Severity']
                            csv_data.append(row)
                    
                    # Add unused ports
                    if analysis['UnusedPorts']:
                        for port in analysis['UnusedPorts']:
                            row = base_row.copy()
                            row['IssueType'] = 'Unused Port'
                            row['Protocol'] = port['Protocol']
                            row['Ports'] = port['Ports']
                            row['Reason'] = port['Reason']
                            csv_data.append(row)
                    
                    # Add redundant rules
                    if analysis['RedundantRules']:
                        for rule in analysis['RedundantRules']:
                            row = base_row.copy()
                            row['IssueType'] = 'Redundant Rule'
                            row['RuleType'] = rule['Type']
                            row['Protocol'] = rule['Protocol']
                            row['Ports'] = rule['Ports']
                            row['Source'] = rule.get('Source', 'N/A')
                            if 'Source1' in rule and 'Source2' in rule:
                                row['Source'] = f"{rule['Source1']} overlaps {rule['Source2']}"
                            row['Reason'] = rule['Reason']
                            csv_data.append(row)
                    
                    # Add compliance issues
                    if analysis['ComplianceIssues']:
                        for issue in analysis['ComplianceIssues']:
                            row = base_row.copy()
                            row['IssueType'] = 'Compliance Issue'
                            row['Standard'] = issue['Standard']
                            row['Control'] = issue['Control']
                            row['Description'] = issue['Description']
                            row['Severity'] = issue['Severity']
                            csv_data.append(row)
                
                # Get all possible keys from all rows
                fieldnames = set()
                for row in csv_data:
                    fieldnames.update(row.keys())
                
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                    writer.writeheader()
                    writer.writerows(csv_data)
            else:
                print(f"{Fore.RED}Unsupported output format: {output_format}{Style.RESET_ALL}")
                return False
            
            print(f"{Fore.GREEN}Successfully exported report to {output_file}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}Error exporting report: {e}{Style.RESET_ALL}")
            return False


def main():
    """Main function to parse arguments and execute commands."""
    parser = argparse.ArgumentParser(description='Security Group Analyzer')
    
    # Global options
    parser.add_argument('--region', help='AWS region (default: from AWS config)')
    parser.add_argument('--profile', help='AWS profile to use')
    
    # Analysis options
    parser.add_argument('--security-group', help='Specific security group ID to analyze')
    parser.add_argument('--check-permissive', action='store_true', help='Check for permissive rules')
    parser.add_argument('--check-unused', action='store_true', help='Check for unused ports')
    parser.add_argument('--check-redundant', action='store_true', help='Check for redundant rules')
    parser.add_argument('--check-compliance', action='store_true', help='Check for compliance issues')
    parser.add_argument('--all-checks', action='store_true', help='Perform all checks')
    
    # Output options
    parser.add_argument('--output-format', choices=['json', 'csv'], help='Output format for report export')
    parser.add_argument('--output-file', help='Output file path for report export')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create security group analyzer
    analyzer = SecurityGroupAnalyzer(region=args.region, profile=args.profile)
    
    # Set check flags if --all-checks is specified
    if args.all_checks:
        args.check_permissive = True
        args.check_unused = True
        args.check_redundant = True
        args.check_compliance = True
    
    # Generate security group report
    analysis_results = analyzer.generate_security_group_report(
        security_group_id=args.security_group,
        check_permissive=args.check_permissive,
        check_unused=args.check_unused,
        check_redundant=args.check_redundant,
        check_compliance=args.check_compliance
    )
    
    # Display analysis results
    if not analysis_results:
        print(f"{Fore.YELLOW}No security groups found matching the criteria.{Style.RESET_ALL}")
    else:
        for analysis in analysis_results:
            analyzer.display_security_group_analysis(analysis)
    
    # Export report if requested
    if args.output_format and args.output_file:
        analyzer.export_report(analysis_results, args.output_format, args.output_file)


if __name__ == '__main__':
    main()
