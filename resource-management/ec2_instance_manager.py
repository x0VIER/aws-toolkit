#!/usr/bin/env python3
"""
EC2 Instance Manager

A comprehensive tool for managing EC2 instances across AWS regions.
Supports launching, stopping, starting, terminating, and reporting on instances.

Author: V Vier
"""

import argparse
import sys
import time
import json
import boto3
from botocore.exceptions import ClientError
from tabulate import tabulate
from colorama import init, Fore, Style

# Initialize colorama
init()

class EC2InstanceManager:
    """Manages EC2 instances across AWS regions."""
    
    def __init__(self, region=None, profile=None):
        """Initialize the EC2 instance manager.
        
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
    
    def launch_instance(self, ami_id, instance_type, key_name=None, security_group_ids=None, 
                       subnet_id=None, user_data=None, name=None, tags=None, count=1):
        """Launch a new EC2 instance.
        
        Args:
            ami_id (str): The AMI ID to use for the instance
            instance_type (str): The instance type (e.g., 't2.micro')
            key_name (str): The key pair name to use
            security_group_ids (list): List of security group IDs
            subnet_id (str): The subnet ID to launch the instance in
            user_data (str): User data script to pass to the instance
            name (str): Name tag for the instance
            tags (dict): Dictionary of tags to apply to the instance
            count (int): Number of instances to launch
            
        Returns:
            list: List of instance IDs that were launched
        """
        try:
            # Prepare the parameters for launching instances
            run_args = {
                'ImageId': ami_id,
                'InstanceType': instance_type,
                'MinCount': 1,
                'MaxCount': count
            }
            
            if key_name:
                run_args['KeyName'] = key_name
                
            if security_group_ids:
                run_args['SecurityGroupIds'] = security_group_ids
                
            if subnet_id:
                run_args['SubnetId'] = subnet_id
                
            if user_data:
                run_args['UserData'] = user_data
                
            # Prepare tags
            tag_specifications = []
            instance_tags = []
            
            if name:
                instance_tags.append({'Key': 'Name', 'Value': name})
                
            if tags:
                for key, value in tags.items():
                    instance_tags.append({'Key': key, 'Value': value})
                    
            if instance_tags:
                tag_specifications.append({
                    'ResourceType': 'instance',
                    'Tags': instance_tags
                })
                
            if tag_specifications:
                run_args['TagSpecifications'] = tag_specifications
            
            # Launch the instances
            response = self.ec2_client.run_instances(**run_args)
            
            # Extract and return the instance IDs
            instance_ids = [instance['InstanceId'] for instance in response['Instances']]
            print(f"{Fore.GREEN}Successfully launched {len(instance_ids)} instance(s){Style.RESET_ALL}")
            for i, instance_id in enumerate(instance_ids):
                print(f"  {i+1}. {instance_id}")
            
            return instance_ids
            
        except ClientError as e:
            print(f"{Fore.RED}Error launching instance: {e}{Style.RESET_ALL}")
            return []
    
    def stop_instances(self, instance_ids=None, tag_key=None, tag_value=None):
        """Stop EC2 instances.
        
        Args:
            instance_ids (list): List of instance IDs to stop
            tag_key (str): Tag key to filter instances
            tag_value (str): Tag value to filter instances
            
        Returns:
            list: List of instance IDs that were stopped
        """
        try:
            # If instance IDs are not provided, find instances by tags
            if not instance_ids and tag_key:
                filters = [{'Name': f'tag:{tag_key}', 'Values': [tag_value]}]
                instances = list(self.ec2_resource.instances.filter(Filters=filters))
                instance_ids = [instance.id for instance in instances if instance.state['Name'] == 'running']
            
            if not instance_ids:
                print(f"{Fore.YELLOW}No running instances found to stop{Style.RESET_ALL}")
                return []
            
            # Stop the instances
            response = self.ec2_client.stop_instances(InstanceIds=instance_ids)
            stopped_instances = [instance['InstanceId'] for instance in response['StoppingInstances']]
            
            print(f"{Fore.GREEN}Successfully initiated stop for {len(stopped_instances)} instance(s){Style.RESET_ALL}")
            for instance_id in stopped_instances:
                print(f"  - {instance_id}")
            
            return stopped_instances
            
        except ClientError as e:
            print(f"{Fore.RED}Error stopping instances: {e}{Style.RESET_ALL}")
            return []
    
    def start_instances(self, instance_ids=None, tag_key=None, tag_value=None):
        """Start EC2 instances.
        
        Args:
            instance_ids (list): List of instance IDs to start
            tag_key (str): Tag key to filter instances
            tag_value (str): Tag value to filter instances
            
        Returns:
            list: List of instance IDs that were started
        """
        try:
            # If instance IDs are not provided, find instances by tags
            if not instance_ids and tag_key:
                filters = [{'Name': f'tag:{tag_key}', 'Values': [tag_value]}]
                instances = list(self.ec2_resource.instances.filter(Filters=filters))
                instance_ids = [instance.id for instance in instances if instance.state['Name'] == 'stopped']
            
            if not instance_ids:
                print(f"{Fore.YELLOW}No stopped instances found to start{Style.RESET_ALL}")
                return []
            
            # Start the instances
            response = self.ec2_client.start_instances(InstanceIds=instance_ids)
            started_instances = [instance['InstanceId'] for instance in response['StartingInstances']]
            
            print(f"{Fore.GREEN}Successfully initiated start for {len(started_instances)} instance(s){Style.RESET_ALL}")
            for instance_id in started_instances:
                print(f"  - {instance_id}")
            
            return started_instances
            
        except ClientError as e:
            print(f"{Fore.RED}Error starting instances: {e}{Style.RESET_ALL}")
            return []
    
    def terminate_instances(self, instance_ids=None, tag_key=None, tag_value=None, force=False):
        """Terminate EC2 instances.
        
        Args:
            instance_ids (list): List of instance IDs to terminate
            tag_key (str): Tag key to filter instances
            tag_value (str): Tag value to filter instances
            force (bool): Force termination without confirmation
            
        Returns:
            list: List of instance IDs that were terminated
        """
        try:
            # If instance IDs are not provided, find instances by tags
            if not instance_ids and tag_key:
                filters = [{'Name': f'tag:{tag_key}', 'Values': [tag_value]}]
                instances = list(self.ec2_resource.instances.filter(Filters=filters))
                instance_ids = [instance.id for instance in instances]
            
            if not instance_ids:
                print(f"{Fore.YELLOW}No instances found to terminate{Style.RESET_ALL}")
                return []
            
            # Get instance details for confirmation
            instances_info = self.get_instances_info(instance_ids)
            
            # Display instances to be terminated
            print(f"{Fore.YELLOW}The following instances will be terminated:{Style.RESET_ALL}")
            headers = ["Instance ID", "Name", "State", "Instance Type", "Launch Time"]
            table_data = []
            
            for instance in instances_info:
                name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
                table_data.append([
                    instance['InstanceId'],
                    name,
                    instance['State']['Name'],
                    instance['InstanceType'],
                    instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
                ])
            
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
            
            # Confirm termination
            if not force:
                confirm = input(f"{Fore.RED}Are you sure you want to terminate these instances? (y/N): {Style.RESET_ALL}")
                if confirm.lower() != 'y':
                    print("Termination cancelled.")
                    return []
            
            # Terminate the instances
            response = self.ec2_client.terminate_instances(InstanceIds=instance_ids)
            terminated_instances = [instance['InstanceId'] for instance in response['TerminatingInstances']]
            
            print(f"{Fore.GREEN}Successfully initiated termination for {len(terminated_instances)} instance(s){Style.RESET_ALL}")
            for instance_id in terminated_instances:
                print(f"  - {instance_id}")
            
            return terminated_instances
            
        except ClientError as e:
            print(f"{Fore.RED}Error terminating instances: {e}{Style.RESET_ALL}")
            return []
    
    def get_instances_info(self, instance_ids=None, filters=None):
        """Get detailed information about EC2 instances.
        
        Args:
            instance_ids (list): List of instance IDs to get info for
            filters (list): List of filters to apply
            
        Returns:
            list: List of instance information dictionaries
        """
        try:
            # Prepare the parameters for describing instances
            describe_args = {}
            
            if instance_ids:
                describe_args['InstanceIds'] = instance_ids
                
            if filters:
                describe_args['Filters'] = filters
            
            # Get instance information
            response = self.ec2_client.describe_instances(**describe_args)
            
            # Extract instance information from the response
            instances_info = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances_info.append(instance)
            
            return instances_info
            
        except ClientError as e:
            print(f"{Fore.RED}Error getting instance information: {e}{Style.RESET_ALL}")
            return []
    
    def display_instances(self, instance_ids=None, tag_key=None, tag_value=None, all_instances=False):
        """Display information about EC2 instances.
        
        Args:
            instance_ids (list): List of instance IDs to display
            tag_key (str): Tag key to filter instances
            tag_value (str): Tag value to filter instances
            all_instances (bool): Whether to display all instances
        """
        try:
            # Prepare filters
            filters = []
            
            if tag_key and tag_value:
                filters.append({'Name': f'tag:{tag_key}', 'Values': [tag_value]})
            
            # Get instance information
            if all_instances:
                instances_info = self.get_instances_info(filters=filters)
            else:
                instances_info = self.get_instances_info(instance_ids=instance_ids, filters=filters)
            
            if not instances_info:
                print(f"{Fore.YELLOW}No instances found matching the criteria{Style.RESET_ALL}")
                return
            
            # Prepare table data
            headers = ["Instance ID", "Name", "State", "Instance Type", "Public IP", "Private IP", "Launch Time"]
            table_data = []
            
            for instance in instances_info:
                name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
                public_ip = instance.get('PublicIpAddress', 'N/A')
                private_ip = instance.get('PrivateIpAddress', 'N/A')
                
                # Color code the state
                state = instance['State']['Name']
                if state == 'running':
                    state = f"{Fore.GREEN}{state}{Style.RESET_ALL}"
                elif state == 'stopped':
                    state = f"{Fore.RED}{state}{Style.RESET_ALL}"
                elif state == 'pending':
                    state = f"{Fore.YELLOW}{state}{Style.RESET_ALL}"
                elif state == 'stopping':
                    state = f"{Fore.YELLOW}{state}{Style.RESET_ALL}"
                
                table_data.append([
                    instance['InstanceId'],
                    name,
                    state,
                    instance['InstanceType'],
                    public_ip,
                    private_ip,
                    instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
                ])
            
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
            
        except ClientError as e:
            print(f"{Fore.RED}Error displaying instances: {e}{Style.RESET_ALL}")
    
    def wait_for_state(self, instance_ids, target_state, timeout=300):
        """Wait for instances to reach a specific state.
        
        Args:
            instance_ids (list): List of instance IDs to wait for
            target_state (str): Target state to wait for (e.g., 'running', 'stopped')
            timeout (int): Maximum time to wait in seconds
            
        Returns:
            bool: True if all instances reached the target state, False otherwise
        """
        print(f"Waiting for instances to reach '{target_state}' state...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            instances_info = self.get_instances_info(instance_ids=instance_ids)
            
            # Check if all instances have reached the target state
            all_reached = all(instance['State']['Name'] == target_state for instance in instances_info)
            
            if all_reached:
                print(f"{Fore.GREEN}All instances have reached '{target_state}' state{Style.RESET_ALL}")
                return True
            
            # Display current states
            states = {instance['InstanceId']: instance['State']['Name'] for instance in instances_info}
            print(f"Current states: {states}")
            
            # Wait before checking again
            time.sleep(10)
        
        print(f"{Fore.RED}Timeout waiting for instances to reach '{target_state}' state{Style.RESET_ALL}")
        return False


def parse_tags(tags_str):
    """Parse tags from a string format (key1=value1,key2=value2)."""
    if not tags_str:
        return {}
    
    tags = {}
    for tag_pair in tags_str.split(','):
        if '=' in tag_pair:
            key, value = tag_pair.split('=', 1)
            tags[key.strip()] = value.strip()
    
    return tags


def main():
    """Main function to parse arguments and execute commands."""
    parser = argparse.ArgumentParser(description='EC2 Instance Manager')
    
    # Global options
    parser.add_argument('--region', help='AWS region (default: from AWS config)')
    parser.add_argument('--profile', help='AWS profile to use')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Launch command
    launch_parser = subparsers.add_parser('launch', help='Launch new EC2 instances')
    launch_parser.add_argument('--ami', required=True, help='AMI ID to use')
    launch_parser.add_argument('--type', required=True, help='Instance type (e.g., t2.micro)')
    launch_parser.add_argument('--key-name', help='Key pair name')
    launch_parser.add_argument('--security-group', action='append', help='Security group ID(s)')
    launch_parser.add_argument('--subnet', help='Subnet ID')
    launch_parser.add_argument('--user-data', help='Path to user data script')
    launch_parser.add_argument('--name', help='Name tag for the instance')
    launch_parser.add_argument('--tags', help='Additional tags (key1=value1,key2=value2)')
    launch_parser.add_argument('--count', type=int, default=1, help='Number of instances to launch')
    
    # Stop command
    stop_parser = subparsers.add_parser('stop', help='Stop EC2 instances')
    stop_parser.add_argument('--ids', action='append', help='Instance ID(s) to stop')
    stop_parser.add_argument('--tag', help='Tag to filter instances (key=value)')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start EC2 instances')
    start_parser.add_argument('--ids', action='append', help='Instance ID(s) to start')
    start_parser.add_argument('--tag', help='Tag to filter instances (key=value)')
    
    # Terminate command
    terminate_parser = subparsers.add_parser('terminate', help='Terminate EC2 instances')
    terminate_parser.add_argument('--ids', action='append', help='Instance ID(s) to terminate')
    terminate_parser.add_argument('--tag', help='Tag to filter instances (key=value)')
    terminate_parser.add_argument('--force', action='store_true', help='Force termination without confirmation')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Display EC2 instance status')
    status_parser.add_argument('--ids', action='append', help='Instance ID(s) to display')
    status_parser.add_argument('--tag', help='Tag to filter instances (key=value)')
    status_parser.add_argument('--all', action='store_true', help='Display all instances')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Check if a command was provided
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Create EC2 instance manager
    manager = EC2InstanceManager(region=args.region, profile=args.profile)
    
    # Execute the requested command
    if args.command == 'launch':
        # Read user data from file if provided
        user_data = None
        if args.user_data:
            try:
                with open(args.user_data, 'r') as f:
                    user_data = f.read()
            except Exception as e:
                print(f"{Fore.RED}Error reading user data file: {e}{Style.RESET_ALL}")
                sys.exit(1)
        
        # Parse tags
        tags = parse_tags(args.tags)
        
        # Launch instances
        instance_ids = manager.launch_instance(
            ami_id=args.ami,
            instance_type=args.type,
            key_name=args.key_name,
            security_group_ids=args.security_group,
            subnet_id=args.subnet,
            user_data=user_data,
            name=args.name,
            tags=tags,
            count=args.count
        )
        
        # Wait for instances to be running
        if instance_ids:
            manager.wait_for_state(instance_ids, 'running')
            manager.display_instances(instance_ids=instance_ids)
    
    elif args.command == 'stop':
        # Parse tag if provided
        tag_key = None
        tag_value = None
        if args.tag:
            if '=' in args.tag:
                tag_key, tag_value = args.tag.split('=', 1)
        
        # Stop instances
        instance_ids = manager.stop_instances(
            instance_ids=args.ids,
            tag_key=tag_key,
            tag_value=tag_value
        )
        
        # Wait for instances to be stopped
        if instance_ids:
            manager.wait_for_state(instance_ids, 'stopped')
    
    elif args.command == 'start':
        # Parse tag if provided
        tag_key = None
        tag_value = None
        if args.tag:
            if '=' in args.tag:
                tag_key, tag_value = args.tag.split('=', 1)
        
        # Start instances
        instance_ids = manager.start_instances(
            instance_ids=args.ids,
            tag_key=tag_key,
            tag_value=tag_value
        )
        
        # Wait for instances to be running
        if instance_ids:
            manager.wait_for_state(instance_ids, 'running')
    
    elif args.command == 'terminate':
        # Parse tag if provided
        tag_key = None
        tag_value = None
        if args.tag:
            if '=' in args.tag:
                tag_key, tag_value = args.tag.split('=', 1)
        
        # Terminate instances
        manager.terminate_instances(
            instance_ids=args.ids,
            tag_key=tag_key,
            tag_value=tag_value,
            force=args.force
        )
    
    elif args.command == 'status':
        # Parse tag if provided
        tag_key = None
        tag_value = None
        if args.tag:
            if '=' in args.tag:
                tag_key, tag_value = args.tag.split('=', 1)
        
        # Display instance status
        manager.display_instances(
            instance_ids=args.ids,
            tag_key=tag_key,
            tag_value=tag_value,
            all_instances=args.all
        )


if __name__ == '__main__':
    main()
