#!/usr/bin/env python3
"""
S3 Bucket Manager

A comprehensive tool for creating and managing S3 buckets with versioning,
lifecycle policies, access controls, and other configurations.

Author: V Vier
"""

import argparse
import sys
import json
import boto3
from botocore.exceptions import ClientError
from tabulate import tabulate
from colorama import init, Fore, Style

# Initialize colorama
init()

class S3BucketManager:
    """Manages S3 buckets across AWS regions."""
    
    def __init__(self, region=None, profile=None):
        """Initialize the S3 bucket manager.
        
        Args:
            region (str): AWS region name (e.g., 'us-east-1')
            profile (str): AWS profile name to use
        """
        self.region = region
        self.profile = profile
        self.session = self._create_session()
        self.s3_client = self.session.client('s3', region_name=self.region)
        self.s3_resource = self.session.resource('s3', region_name=self.region)
    
    def _create_session(self):
        """Create a boto3 session with the specified profile if provided."""
        if self.profile:
            return boto3.Session(profile_name=self.profile, region_name=self.region)
        return boto3.Session(region_name=self.region)
    
    def create_bucket(self, bucket_name, acl=None, region=None, tags=None):
        """Create a new S3 bucket.
        
        Args:
            bucket_name (str): Name of the bucket to create
            acl (str): Canned ACL to apply (e.g., 'private', 'public-read')
            region (str): Region to create the bucket in (overrides instance region)
            tags (dict): Dictionary of tags to apply to the bucket
            
        Returns:
            bool: True if bucket was created successfully, False otherwise
        """
        try:
            # Prepare the parameters for creating the bucket
            create_args = {
                'Bucket': bucket_name
            }
            
            if acl:
                create_args['ACL'] = acl
            
            # Use the specified region or the instance region
            bucket_region = region or self.region
            
            # For regions other than us-east-1, we need to specify the location constraint
            if bucket_region and bucket_region != 'us-east-1':
                create_args['CreateBucketConfiguration'] = {
                    'LocationConstraint': bucket_region
                }
            
            # Create the bucket
            self.s3_client.create_bucket(**create_args)
            
            print(f"{Fore.GREEN}Successfully created bucket: {bucket_name}{Style.RESET_ALL}")
            
            # Apply tags if provided
            if tags:
                tag_set = [{'Key': key, 'Value': value} for key, value in tags.items()]
                self.s3_client.put_bucket_tagging(
                    Bucket=bucket_name,
                    Tagging={'TagSet': tag_set}
                )
                print(f"{Fore.GREEN}Applied tags to bucket: {bucket_name}{Style.RESET_ALL}")
            
            return True
            
        except ClientError as e:
            print(f"{Fore.RED}Error creating bucket: {e}{Style.RESET_ALL}")
            return False
    
    def delete_bucket(self, bucket_name, force=False):
        """Delete an S3 bucket.
        
        Args:
            bucket_name (str): Name of the bucket to delete
            force (bool): Whether to force deletion by removing all objects first
            
        Returns:
            bool: True if bucket was deleted successfully, False otherwise
        """
        try:
            # Check if the bucket exists
            try:
                self.s3_client.head_bucket(Bucket=bucket_name)
            except ClientError as e:
                if e.response['Error']['Code'] == '404':
                    print(f"{Fore.YELLOW}Bucket does not exist: {bucket_name}{Style.RESET_ALL}")
                    return False
                else:
                    raise
            
            # If force is True, delete all objects in the bucket first
            if force:
                bucket = self.s3_resource.Bucket(bucket_name)
                
                # Check if versioning is enabled
                versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
                versioning_status = versioning.get('Status', 'Disabled')
                
                if versioning_status == 'Enabled':
                    # Delete all versions and delete markers
                    print(f"{Fore.YELLOW}Deleting all object versions from bucket: {bucket_name}{Style.RESET_ALL}")
                    bucket.object_versions.delete()
                else:
                    # Delete all objects
                    print(f"{Fore.YELLOW}Deleting all objects from bucket: {bucket_name}{Style.RESET_ALL}")
                    bucket.objects.all().delete()
            
            # Delete the bucket
            self.s3_client.delete_bucket(Bucket=bucket_name)
            
            print(f"{Fore.GREEN}Successfully deleted bucket: {bucket_name}{Style.RESET_ALL}")
            return True
            
        except ClientError as e:
            print(f"{Fore.RED}Error deleting bucket: {e}{Style.RESET_ALL}")
            return False
    
    def enable_versioning(self, bucket_name):
        """Enable versioning on an S3 bucket.
        
        Args:
            bucket_name (str): Name of the bucket
            
        Returns:
            bool: True if versioning was enabled successfully, False otherwise
        """
        try:
            self.s3_client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            
            print(f"{Fore.GREEN}Successfully enabled versioning on bucket: {bucket_name}{Style.RESET_ALL}")
            return True
            
        except ClientError as e:
            print(f"{Fore.RED}Error enabling versioning: {e}{Style.RESET_ALL}")
            return False
    
    def disable_versioning(self, bucket_name):
        """Suspend versioning on an S3 bucket.
        
        Args:
            bucket_name (str): Name of the bucket
            
        Returns:
            bool: True if versioning was suspended successfully, False otherwise
        """
        try:
            self.s3_client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Suspended'}
            )
            
            print(f"{Fore.GREEN}Successfully suspended versioning on bucket: {bucket_name}{Style.RESET_ALL}")
            return True
            
        except ClientError as e:
            print(f"{Fore.RED}Error suspending versioning: {e}{Style.RESET_ALL}")
            return False
    
    def set_lifecycle_policy(self, bucket_name, policy_file=None, policy_json=None):
        """Set a lifecycle policy on an S3 bucket.
        
        Args:
            bucket_name (str): Name of the bucket
            policy_file (str): Path to a JSON file containing the lifecycle policy
            policy_json (str): JSON string containing the lifecycle policy
            
        Returns:
            bool: True if policy was set successfully, False otherwise
        """
        try:
            # Load policy from file or string
            if policy_file:
                try:
                    with open(policy_file, 'r') as f:
                        policy = json.load(f)
                except Exception as e:
                    print(f"{Fore.RED}Error reading policy file: {e}{Style.RESET_ALL}")
                    return False
            elif policy_json:
                try:
                    policy = json.loads(policy_json)
                except Exception as e:
                    print(f"{Fore.RED}Error parsing policy JSON: {e}{Style.RESET_ALL}")
                    return False
            else:
                print(f"{Fore.RED}No policy provided{Style.RESET_ALL}")
                return False
            
            # Set the lifecycle policy
            self.s3_client.put_bucket_lifecycle_configuration(
                Bucket=bucket_name,
                LifecycleConfiguration=policy
            )
            
            print(f"{Fore.GREEN}Successfully set lifecycle policy on bucket: {bucket_name}{Style.RESET_ALL}")
            return True
            
        except ClientError as e:
            print(f"{Fore.RED}Error setting lifecycle policy: {e}{Style.RESET_ALL}")
            return False
    
    def set_bucket_policy(self, bucket_name, policy_file=None, policy_json=None):
        """Set a bucket policy on an S3 bucket.
        
        Args:
            bucket_name (str): Name of the bucket
            policy_file (str): Path to a JSON file containing the bucket policy
            policy_json (str): JSON string containing the bucket policy
            
        Returns:
            bool: True if policy was set successfully, False otherwise
        """
        try:
            # Load policy from file or string
            if policy_file:
                try:
                    with open(policy_file, 'r') as f:
                        policy = json.load(f)
                        policy_str = json.dumps(policy)
                except Exception as e:
                    print(f"{Fore.RED}Error reading policy file: {e}{Style.RESET_ALL}")
                    return False
            elif policy_json:
                try:
                    # Validate JSON
                    json.loads(policy_json)
                    policy_str = policy_json
                except Exception as e:
                    print(f"{Fore.RED}Error parsing policy JSON: {e}{Style.RESET_ALL}")
                    return False
            else:
                print(f"{Fore.RED}No policy provided{Style.RESET_ALL}")
                return False
            
            # Set the bucket policy
            self.s3_client.put_bucket_policy(
                Bucket=bucket_name,
                Policy=policy_str
            )
            
            print(f"{Fore.GREEN}Successfully set bucket policy on bucket: {bucket_name}{Style.RESET_ALL}")
            return True
            
        except ClientError as e:
            print(f"{Fore.RED}Error setting bucket policy: {e}{Style.RESET_ALL}")
            return False
    
    def enable_encryption(self, bucket_name, kms_key_id=None):
        """Enable default encryption on an S3 bucket.
        
        Args:
            bucket_name (str): Name of the bucket
            kms_key_id (str): KMS key ID to use for encryption (optional)
            
        Returns:
            bool: True if encryption was enabled successfully, False otherwise
        """
        try:
            # Prepare encryption configuration
            encryption_config = {
                'ServerSideEncryptionConfiguration': {
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }
                    ]
                }
            }
            
            # If KMS key ID is provided, use SSE-KMS instead of SSE-S3
            if kms_key_id:
                encryption_config['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault'] = {
                    'SSEAlgorithm': 'aws:kms',
                    'KMSMasterKeyID': kms_key_id
                }
            
            # Set the encryption configuration
            self.s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                **encryption_config
            )
            
            print(f"{Fore.GREEN}Successfully enabled encryption on bucket: {bucket_name}{Style.RESET_ALL}")
            return True
            
        except ClientError as e:
            print(f"{Fore.RED}Error enabling encryption: {e}{Style.RESET_ALL}")
            return False
    
    def list_buckets(self, show_details=False):
        """List all S3 buckets.
        
        Args:
            show_details (bool): Whether to show detailed information about each bucket
            
        Returns:
            list: List of bucket names
        """
        try:
            # Get list of buckets
            response = self.s3_client.list_buckets()
            buckets = response['Buckets']
            
            if not buckets:
                print(f"{Fore.YELLOW}No buckets found{Style.RESET_ALL}")
                return []
            
            # Display bucket information
            if show_details:
                headers = ["Bucket Name", "Creation Date", "Region", "Versioning", "Public Access"]
                table_data = []
                
                for bucket in buckets:
                    bucket_name = bucket['Name']
                    creation_date = bucket['CreationDate'].strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Get bucket region
                    try:
                        location = self.s3_client.get_bucket_location(Bucket=bucket_name)
                        region = location['LocationConstraint'] or 'us-east-1'
                    except Exception:
                        region = 'N/A'
                    
                    # Get versioning status
                    try:
                        versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
                        versioning_status = versioning.get('Status', 'Disabled')
                    except Exception:
                        versioning_status = 'N/A'
                    
                    # Get public access block configuration
                    try:
                        public_access = self.s3_client.get_public_access_block(Bucket=bucket_name)
                        is_public = not all(public_access['PublicAccessBlockConfiguration'].values())
                        public_status = f"{Fore.RED}Public{Style.RESET_ALL}" if is_public else f"{Fore.GREEN}Blocked{Style.RESET_ALL}"
                    except Exception:
                        public_status = 'Unknown'
                    
                    table_data.append([
                        bucket_name,
                        creation_date,
                        region,
                        versioning_status,
                        public_status
                    ])
                
                print(tabulate(table_data, headers=headers, tablefmt="grid"))
            else:
                # Simple list of bucket names
                for bucket in buckets:
                    print(bucket['Name'])
            
            return [bucket['Name'] for bucket in buckets]
            
        except ClientError as e:
            print(f"{Fore.RED}Error listing buckets: {e}{Style.RESET_ALL}")
            return []
    
    def block_public_access(self, bucket_name):
        """Block all public access to an S3 bucket.
        
        Args:
            bucket_name (str): Name of the bucket
            
        Returns:
            bool: True if public access was blocked successfully, False otherwise
        """
        try:
            self.s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            print(f"{Fore.GREEN}Successfully blocked public access to bucket: {bucket_name}{Style.RESET_ALL}")
            return True
            
        except ClientError as e:
            print(f"{Fore.RED}Error blocking public access: {e}{Style.RESET_ALL}")
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
    parser = argparse.ArgumentParser(description='S3 Bucket Manager')
    
    # Global options
    parser.add_argument('--region', help='AWS region (default: from AWS config)')
    parser.add_argument('--profile', help='AWS profile to use')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Create bucket command
    create_parser = subparsers.add_parser('create', help='Create a new S3 bucket')
    create_parser.add_argument('--name', required=True, help='Name of the bucket to create')
    create_parser.add_argument('--acl', choices=['private', 'public-read', 'public-read-write', 'authenticated-read'], 
                              help='Canned ACL to apply')
    create_parser.add_argument('--region', help='Region to create the bucket in')
    create_parser.add_argument('--tags', help='Tags to apply (key1=value1,key2=value2)')
    
    # Delete bucket command
    delete_parser = subparsers.add_parser('delete', help='Delete an S3 bucket')
    delete_parser.add_argument('--name', required=True, help='Name of the bucket to delete')
    delete_parser.add_argument('--force', action='store_true', help='Force deletion by removing all objects first')
    
    # Enable versioning command
    versioning_parser = subparsers.add_parser('versioning', help='Manage bucket versioning')
    versioning_parser.add_argument('--name', required=True, help='Name of the bucket')
    versioning_parser.add_argument('--enable', action='store_true', help='Enable versioning')
    versioning_parser.add_argument('--disable', action='store_true', help='Disable versioning')
    
    # Set lifecycle policy command
    lifecycle_parser = subparsers.add_parser('lifecycle', help='Set lifecycle policy')
    lifecycle_parser.add_argument('--name', required=True, help='Name of the bucket')
    lifecycle_parser.add_argument('--file', help='Path to JSON file containing lifecycle policy')
    lifecycle_parser.add_argument('--json', help='JSON string containing lifecycle policy')
    
    # Set bucket policy command
    policy_parser = subparsers.add_parser('policy', help='Set bucket policy')
    policy_parser.add_argument('--name', required=True, help='Name of the bucket')
    policy_parser.add_argument('--file', help='Path to JSON file containing bucket policy')
    policy_parser.add_argument('--json', help='JSON string containing bucket policy')
    
    # Enable encryption command
    encryption_parser = subparsers.add_parser('encryption', help='Enable default encryption')
    encryption_parser.add_argument('--name', required=True, help='Name of the bucket')
    encryption_parser.add_argument('--kms-key', help='KMS key ID to use for encryption')
    
    # List buckets command
    list_parser = subparsers.add_parser('list', help='List S3 buckets')
    list_parser.add_argument('--details', action='store_true', help='Show detailed information')
    
    # Block public access command
    public_parser = subparsers.add_parser('block-public', help='Block all public access')
    public_parser.add_argument('--name', required=True, help='Name of the bucket')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Check if a command was provided
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Create S3 bucket manager
    manager = S3BucketManager(region=args.region, profile=args.profile)
    
    # Execute the requested command
    if args.command == 'create':
        # Parse tags
        tags = parse_tags(args.tags)
        
        # Create bucket
        manager.create_bucket(
            bucket_name=args.name,
            acl=args.acl,
            region=args.region,
            tags=tags
        )
    
    elif args.command == 'delete':
        # Delete bucket
        manager.delete_bucket(
            bucket_name=args.name,
            force=args.force
        )
    
    elif args.command == 'versioning':
        # Check if enable or disable was specified
        if args.enable and args.disable:
            print(f"{Fore.RED}Cannot both enable and disable versioning{Style.RESET_ALL}")
            sys.exit(1)
        elif args.enable:
            manager.enable_versioning(bucket_name=args.name)
        elif args.disable:
            manager.disable_versioning(bucket_name=args.name)
        else:
            print(f"{Fore.RED}Must specify either --enable or --disable{Style.RESET_ALL}")
            sys.exit(1)
    
    elif args.command == 'lifecycle':
        # Check if file or JSON was provided
        if not args.file and not args.json:
            print(f"{Fore.RED}Must provide either --file or --json{Style.RESET_ALL}")
            sys.exit(1)
        
        # Set lifecycle policy
        manager.set_lifecycle_policy(
            bucket_name=args.name,
            policy_file=args.file,
            policy_json=args.json
        )
    
    elif args.command == 'policy':
        # Check if file or JSON was provided
        if not args.file and not args.json:
            print(f"{Fore.RED}Must provide either --file or --json{Style.RESET_ALL}")
            sys.exit(1)
        
        # Set bucket policy
        manager.set_bucket_policy(
            bucket_name=args.name,
            policy_file=args.file,
            policy_json=args.json
        )
    
    elif args.command == 'encryption':
        # Enable encryption
        manager.enable_encryption(
            bucket_name=args.name,
            kms_key_id=args.kms_key
        )
    
    elif args.command == 'list':
        # List buckets
        manager.list_buckets(show_details=args.details)
    
    elif args.command == 'block-public':
        # Block public access
        manager.block_public_access(bucket_name=args.name)


if __name__ == '__main__':
    main()
