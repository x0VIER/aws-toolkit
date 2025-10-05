#!/usr/bin/env python3
"""
IAM User Audit Tool

A comprehensive tool for auditing IAM users in AWS accounts.
Identifies security risks such as users without MFA, inactive users,
and users with overly permissive policies.

Author: V Vier
"""

import argparse
import sys
import json
import csv
import datetime
import boto3
from botocore.exceptions import ClientError
from tabulate import tabulate
from colorama import init, Fore, Style

# Initialize colorama
init()

class IAMUserAuditor:
    """Audits IAM users across AWS accounts."""
    
    def __init__(self, profile=None):
        """Initialize the IAM user auditor.
        
        Args:
            profile (str): AWS profile name to use
        """
        self.profile = profile
        self.session = self._create_session()
        self.iam_client = self.session.client('iam')
        self.iam_resource = self.session.resource('iam')
    
    def _create_session(self):
        """Create a boto3 session with the specified profile if provided."""
        if self.profile:
            return boto3.Session(profile_name=self.profile)
        return boto3.Session()
    
    def get_all_users(self):
        """Get all IAM users in the account.
        
        Returns:
            list: List of IAM user dictionaries
        """
        try:
            users = []
            paginator = self.iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                users.extend(page['Users'])
            
            return users
        except ClientError as e:
            print(f"{Fore.RED}Error getting IAM users: {e}{Style.RESET_ALL}")
            return []
    
    def get_user_details(self, user_name):
        """Get detailed information about an IAM user.
        
        Args:
            user_name (str): Name of the IAM user
            
        Returns:
            dict: Dictionary containing user details
        """
        try:
            user_details = {
                'UserName': user_name,
                'AccessKeys': [],
                'MFADevices': [],
                'Groups': [],
                'Policies': [],
                'LastActivity': None,
                'HasConsoleAccess': False,
                'PasswordLastUsed': None,
                'PasswordLastChanged': None,
                'AccessKeyLastUsed': None
            }
            
            # Get user information
            user = self.iam_resource.User(user_name)
            
            # Check if user has console access
            try:
                login_profile = self.iam_client.get_login_profile(UserName=user_name)
                user_details['HasConsoleAccess'] = True
                
                # Get password last used date
                if hasattr(user, 'password_last_used') and user.password_last_used:
                    user_details['PasswordLastUsed'] = user.password_last_used
                    
                    # Update last activity if password was used
                    if not user_details['LastActivity'] or user.password_last_used > user_details['LastActivity']:
                        user_details['LastActivity'] = user.password_last_used
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    user_details['HasConsoleAccess'] = False
                else:
                    raise
            
            # Get access keys
            for key in user.access_keys.all():
                key_info = {
                    'AccessKeyId': key.access_key_id,
                    'Status': key.status,
                    'CreateDate': key.create_date,
                    'LastUsed': None
                }
                
                # Get last used information
                try:
                    last_used = self.iam_client.get_access_key_last_used(AccessKeyId=key.access_key_id)
                    if 'LastUsedDate' in last_used['AccessKeyLastUsed']:
                        key_info['LastUsed'] = last_used['AccessKeyLastUsed']['LastUsedDate']
                        
                        # Update last activity if access key was used
                        if not user_details['LastActivity'] or key_info['LastUsed'] > user_details['LastActivity']:
                            user_details['LastActivity'] = key_info['LastUsed']
                        
                        # Update access key last used
                        if not user_details['AccessKeyLastUsed'] or key_info['LastUsed'] > user_details['AccessKeyLastUsed']:
                            user_details['AccessKeyLastUsed'] = key_info['LastUsed']
                except ClientError:
                    pass
                
                user_details['AccessKeys'].append(key_info)
            
            # Get MFA devices
            for mfa in user.mfa_devices.all():
                user_details['MFADevices'].append({
                    'SerialNumber': mfa.serial_number,
                    'EnableDate': mfa.enable_date
                })
            
            # Get groups
            for group in user.groups.all():
                user_details['Groups'].append(group.name)
            
            # Get attached policies
            for policy in user.attached_policies.all():
                user_details['Policies'].append({
                    'PolicyName': policy.policy_name,
                    'PolicyArn': policy.arn
                })
            
            # Get inline policies
            for policy_name in user.policies.all():
                user_details['Policies'].append({
                    'PolicyName': policy_name.name,
                    'PolicyType': 'Inline'
                })
            
            return user_details
        except ClientError as e:
            print(f"{Fore.RED}Error getting details for user {user_name}: {e}{Style.RESET_ALL}")
            return None
    
    def check_user_security(self, user_details):
        """Check for security issues with an IAM user.
        
        Args:
            user_details (dict): Dictionary containing user details
            
        Returns:
            dict: Dictionary containing security issues
        """
        issues = {
            'NoMFA': False,
            'InactiveUser': False,
            'OldAccessKeys': [],
            'ActiveUnusedAccessKeys': [],
            'OverlyPermissivePolicy': [],
            'PasswordPolicy': []
        }
        
        # Check if user has MFA enabled
        if not user_details['MFADevices'] and user_details['HasConsoleAccess']:
            issues['NoMFA'] = True
        
        # Check for inactive users (no activity in the last 90 days)
        if user_details['LastActivity']:
            days_since_activity = (datetime.datetime.now(datetime.timezone.utc) - user_details['LastActivity']).days
            if days_since_activity > 90:
                issues['InactiveUser'] = True
        elif user_details['HasConsoleAccess'] or user_details['AccessKeys']:
            # User has access but no recorded activity
            issues['InactiveUser'] = True
        
        # Check for old access keys (older than 90 days)
        for key in user_details['AccessKeys']:
            days_since_creation = (datetime.datetime.now(datetime.timezone.utc) - key['CreateDate']).days
            if days_since_creation > 90:
                issues['OldAccessKeys'].append({
                    'AccessKeyId': key['AccessKeyId'],
                    'Age': days_since_creation
                })
            
            # Check for active but unused access keys
            if key['Status'] == 'Active' and not key['LastUsed']:
                issues['ActiveUnusedAccessKeys'].append({
                    'AccessKeyId': key['AccessKeyId'],
                    'Age': days_since_creation
                })
        
        # Check for overly permissive policies
        for policy in user_details['Policies']:
            if 'PolicyArn' in policy and policy['PolicyArn'].endswith('AdministratorAccess'):
                issues['OverlyPermissivePolicy'].append({
                    'PolicyName': policy['PolicyName'],
                    'PolicyArn': policy['PolicyArn']
                })
            elif 'PolicyArn' in policy and policy['PolicyArn'].endswith('FullAccess'):
                issues['OverlyPermissivePolicy'].append({
                    'PolicyName': policy['PolicyName'],
                    'PolicyArn': policy['PolicyArn']
                })
        
        # Check password policy compliance
        if user_details['HasConsoleAccess'] and user_details['PasswordLastChanged']:
            days_since_password_change = (datetime.datetime.now(datetime.timezone.utc) - user_details['PasswordLastChanged']).days
            if days_since_password_change > 90:
                issues['PasswordPolicy'].append({
                    'Issue': 'Password not changed in the last 90 days',
                    'DaysSinceChange': days_since_password_change
                })
        
        return issues
    
    def generate_user_report(self, user_name=None, find_issues=False):
        """Generate a report for IAM users.
        
        Args:
            user_name (str): Name of a specific IAM user to report on
            find_issues (bool): Whether to only report users with security issues
            
        Returns:
            list: List of user reports
        """
        try:
            user_reports = []
            
            # Get all users or a specific user
            if user_name:
                users = [{'UserName': user_name}]
            else:
                users = self.get_all_users()
            
            # Process each user
            for user in users:
                user_details = self.get_user_details(user['UserName'])
                if not user_details:
                    continue
                
                # Check for security issues
                security_issues = self.check_user_security(user_details)
                
                # Skip users without issues if find_issues is True
                if find_issues and not any(security_issues.values()):
                    continue
                
                # Create user report
                user_report = {
                    'UserName': user_details['UserName'],
                    'HasConsoleAccess': user_details['HasConsoleAccess'],
                    'MFAEnabled': len(user_details['MFADevices']) > 0,
                    'AccessKeyCount': len(user_details['AccessKeys']),
                    'GroupCount': len(user_details['Groups']),
                    'PolicyCount': len(user_details['Policies']),
                    'LastActivity': user_details['LastActivity'],
                    'SecurityIssues': security_issues
                }
                
                user_reports.append(user_report)
            
            return user_reports
        except ClientError as e:
            print(f"{Fore.RED}Error generating user report: {e}{Style.RESET_ALL}")
            return []
    
    def display_user_report(self, user_reports):
        """Display a report of IAM users.
        
        Args:
            user_reports (list): List of user reports
        """
        if not user_reports:
            print(f"{Fore.YELLOW}No users to report.{Style.RESET_ALL}")
            return
        
        # Prepare table data
        headers = ["Username", "Console Access", "MFA", "Access Keys", "Groups", "Policies", "Last Activity", "Security Issues"]
        table_data = []
        
        for report in user_reports:
            # Format last activity
            last_activity = report['LastActivity'].strftime('%Y-%m-%d') if report['LastActivity'] else 'Never'
            
            # Count security issues
            issue_count = 0
            for key, value in report['SecurityIssues'].items():
                if isinstance(value, bool) and value:
                    issue_count += 1
                elif isinstance(value, list) and value:
                    issue_count += len(value)
            
            # Format security issues
            if issue_count > 0:
                security_issues = f"{Fore.RED}{issue_count} issue(s){Style.RESET_ALL}"
            else:
                security_issues = f"{Fore.GREEN}None{Style.RESET_ALL}"
            
            # Format MFA status
            mfa_status = f"{Fore.GREEN}Enabled{Style.RESET_ALL}" if report['MFAEnabled'] else f"{Fore.RED}Disabled{Style.RESET_ALL}"
            
            table_data.append([
                report['UserName'],
                "Yes" if report['HasConsoleAccess'] else "No",
                mfa_status,
                report['AccessKeyCount'],
                report['GroupCount'],
                report['PolicyCount'],
                last_activity,
                security_issues
            ])
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nTotal users: {len(user_reports)}")
    
    def display_security_issues(self, user_reports):
        """Display security issues for IAM users.
        
        Args:
            user_reports (list): List of user reports
        """
        if not user_reports:
            print(f"{Fore.YELLOW}No users to report.{Style.RESET_ALL}")
            return
        
        # Count issues by type
        issue_counts = {
            'NoMFA': 0,
            'InactiveUser': 0,
            'OldAccessKeys': 0,
            'ActiveUnusedAccessKeys': 0,
            'OverlyPermissivePolicy': 0,
            'PasswordPolicy': 0
        }
        
        for report in user_reports:
            issues = report['SecurityIssues']
            if issues['NoMFA']:
                issue_counts['NoMFA'] += 1
            if issues['InactiveUser']:
                issue_counts['InactiveUser'] += 1
            if issues['OldAccessKeys']:
                issue_counts['OldAccessKeys'] += len(issues['OldAccessKeys'])
            if issues['ActiveUnusedAccessKeys']:
                issue_counts['ActiveUnusedAccessKeys'] += len(issues['ActiveUnusedAccessKeys'])
            if issues['OverlyPermissivePolicy']:
                issue_counts['OverlyPermissivePolicy'] += len(issues['OverlyPermissivePolicy'])
            if issues['PasswordPolicy']:
                issue_counts['PasswordPolicy'] += len(issues['PasswordPolicy'])
        
        # Display issue summary
        print(f"{Fore.YELLOW}Security Issue Summary:{Style.RESET_ALL}")
        print(f"  Users without MFA: {issue_counts['NoMFA']}")
        print(f"  Inactive users: {issue_counts['InactiveUser']}")
        print(f"  Old access keys (>90 days): {issue_counts['OldAccessKeys']}")
        print(f"  Active but unused access keys: {issue_counts['ActiveUnusedAccessKeys']}")
        print(f"  Overly permissive policies: {issue_counts['OverlyPermissivePolicy']}")
        print(f"  Password policy violations: {issue_counts['PasswordPolicy']}")
        print()
        
        # Display detailed issues
        print(f"{Fore.YELLOW}Detailed Security Issues:{Style.RESET_ALL}")
        
        # Users without MFA
        if issue_counts['NoMFA'] > 0:
            print(f"\n{Fore.RED}Users without MFA:{Style.RESET_ALL}")
            for report in user_reports:
                if report['SecurityIssues']['NoMFA']:
                    print(f"  - {report['UserName']}")
        
        # Inactive users
        if issue_counts['InactiveUser'] > 0:
            print(f"\n{Fore.RED}Inactive users (no activity in 90+ days):{Style.RESET_ALL}")
            for report in user_reports:
                if report['SecurityIssues']['InactiveUser']:
                    last_activity = report['LastActivity'].strftime('%Y-%m-%d') if report['LastActivity'] else 'Never'
                    print(f"  - {report['UserName']} (Last activity: {last_activity})")
        
        # Old access keys
        if issue_counts['OldAccessKeys'] > 0:
            print(f"\n{Fore.RED}Old access keys (>90 days):{Style.RESET_ALL}")
            for report in user_reports:
                for key in report['SecurityIssues']['OldAccessKeys']:
                    print(f"  - {report['UserName']}: {key['AccessKeyId']} (Age: {key['Age']} days)")
        
        # Active but unused access keys
        if issue_counts['ActiveUnusedAccessKeys'] > 0:
            print(f"\n{Fore.RED}Active but unused access keys:{Style.RESET_ALL}")
            for report in user_reports:
                for key in report['SecurityIssues']['ActiveUnusedAccessKeys']:
                    print(f"  - {report['UserName']}: {key['AccessKeyId']} (Age: {key['Age']} days)")
        
        # Overly permissive policies
        if issue_counts['OverlyPermissivePolicy'] > 0:
            print(f"\n{Fore.RED}Overly permissive policies:{Style.RESET_ALL}")
            for report in user_reports:
                for policy in report['SecurityIssues']['OverlyPermissivePolicy']:
                    print(f"  - {report['UserName']}: {policy['PolicyName']}")
        
        # Password policy violations
        if issue_counts['PasswordPolicy'] > 0:
            print(f"\n{Fore.RED}Password policy violations:{Style.RESET_ALL}")
            for report in user_reports:
                for violation in report['SecurityIssues']['PasswordPolicy']:
                    print(f"  - {report['UserName']}: {violation['Issue']} ({violation['DaysSinceChange']} days)")
    
    def generate_compliance_report(self, user_reports):
        """Generate a compliance report for IAM users.
        
        Args:
            user_reports (list): List of user reports
            
        Returns:
            dict: Dictionary containing compliance metrics
        """
        if not user_reports:
            return {
                'TotalUsers': 0,
                'ComplianceScore': 100,
                'ComplianceIssues': {}
            }
        
        # Initialize compliance metrics
        compliance = {
            'TotalUsers': len(user_reports),
            'UsersWithMFA': 0,
            'UsersWithoutMFA': 0,
            'InactiveUsers': 0,
            'UsersWithOldAccessKeys': 0,
            'UsersWithUnusedAccessKeys': 0,
            'UsersWithOverlyPermissivePolicies': 0,
            'UsersWithPasswordPolicyViolations': 0,
            'ComplianceScore': 0,
            'ComplianceIssues': {}
        }
        
        # Calculate compliance metrics
        for report in user_reports:
            issues = report['SecurityIssues']
            
            # MFA compliance
            if report['MFAEnabled']:
                compliance['UsersWithMFA'] += 1
            else:
                compliance['UsersWithoutMFA'] += 1
            
            # Other compliance issues
            if issues['InactiveUser']:
                compliance['InactiveUsers'] += 1
            if issues['OldAccessKeys']:
                compliance['UsersWithOldAccessKeys'] += 1
            if issues['ActiveUnusedAccessKeys']:
                compliance['UsersWithUnusedAccessKeys'] += 1
            if issues['OverlyPermissivePolicy']:
                compliance['UsersWithOverlyPermissivePolicies'] += 1
            if issues['PasswordPolicy']:
                compliance['UsersWithPasswordPolicyViolations'] += 1
        
        # Calculate compliance score
        total_issues = (
            compliance['UsersWithoutMFA'] +
            compliance['InactiveUsers'] +
            compliance['UsersWithOldAccessKeys'] +
            compliance['UsersWithUnusedAccessKeys'] +
            compliance['UsersWithOverlyPermissivePolicies'] +
            compliance['UsersWithPasswordPolicyViolations']
        )
        
        max_possible_issues = compliance['TotalUsers'] * 6  # 6 types of issues
        compliance_score = 100 - (total_issues / max_possible_issues * 100) if max_possible_issues > 0 else 100
        compliance['ComplianceScore'] = round(compliance_score, 2)
        
        # Compile compliance issues
        compliance['ComplianceIssues'] = {
            'MFACompliance': round(compliance['UsersWithMFA'] / compliance['TotalUsers'] * 100, 2) if compliance['TotalUsers'] > 0 else 100,
            'InactiveUserPercentage': round(compliance['InactiveUsers'] / compliance['TotalUsers'] * 100, 2) if compliance['TotalUsers'] > 0 else 0,
            'OldAccessKeyPercentage': round(compliance['UsersWithOldAccessKeys'] / compliance['TotalUsers'] * 100, 2) if compliance['TotalUsers'] > 0 else 0,
            'UnusedAccessKeyPercentage': round(compliance['UsersWithUnusedAccessKeys'] / compliance['TotalUsers'] * 100, 2) if compliance['TotalUsers'] > 0 else 0,
            'OverlyPermissivePolicyPercentage': round(compliance['UsersWithOverlyPermissivePolicies'] / compliance['TotalUsers'] * 100, 2) if compliance['TotalUsers'] > 0 else 0,
            'PasswordPolicyViolationPercentage': round(compliance['UsersWithPasswordPolicyViolations'] / compliance['TotalUsers'] * 100, 2) if compliance['TotalUsers'] > 0 else 0
        }
        
        return compliance
    
    def display_compliance_report(self, compliance):
        """Display a compliance report.
        
        Args:
            compliance (dict): Dictionary containing compliance metrics
        """
        print(f"{Fore.YELLOW}IAM User Compliance Report:{Style.RESET_ALL}")
        print(f"Total Users: {compliance['TotalUsers']}")
        
        # Display compliance score
        score = compliance['ComplianceScore']
        if score >= 90:
            print(f"Compliance Score: {Fore.GREEN}{score}%{Style.RESET_ALL}")
        elif score >= 70:
            print(f"Compliance Score: {Fore.YELLOW}{score}%{Style.RESET_ALL}")
        else:
            print(f"Compliance Score: {Fore.RED}{score}%{Style.RESET_ALL}")
        
        # Display compliance metrics
        print("\nCompliance Metrics:")
        
        issues = compliance['ComplianceIssues']
        metrics = [
            ("MFA Compliance", issues['MFACompliance'], 90),
            ("Active User Percentage", 100 - issues['InactiveUserPercentage'], 80),
            ("Access Key Rotation", 100 - issues['OldAccessKeyPercentage'], 90),
            ("Access Key Usage", 100 - issues['UnusedAccessKeyPercentage'], 80),
            ("Least Privilege", 100 - issues['OverlyPermissivePolicyPercentage'], 95),
            ("Password Policy", 100 - issues['PasswordPolicyViolationPercentage'], 90)
        ]
        
        headers = ["Metric", "Score", "Target", "Status"]
        table_data = []
        
        for metric, score, target in metrics:
            if score >= target:
                status = f"{Fore.GREEN}Pass{Style.RESET_ALL}"
            else:
                status = f"{Fore.RED}Fail{Style.RESET_ALL}"
            
            table_data.append([metric, f"{score}%", f"{target}%", status])
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    def export_report(self, user_reports, output_format, output_file):
        """Export a report to a file.
        
        Args:
            user_reports (list): List of user reports
            output_format (str): Output format (json or csv)
            output_file (str): Output file path
            
        Returns:
            bool: True if export was successful, False otherwise
        """
        try:
            # Prepare data for export
            export_data = []
            for report in user_reports:
                # Create a copy of the report for export
                export_report = report.copy()
                
                # Convert datetime objects to strings
                if export_report['LastActivity']:
                    export_report['LastActivity'] = export_report['LastActivity'].strftime('%Y-%m-%d %H:%M:%S')
                
                export_data.append(export_report)
            
            # Export to the specified format
            if output_format == 'json':
                with open(output_file, 'w') as f:
                    json.dump(export_data, f, indent=2)
            elif output_format == 'csv':
                if not export_data:
                    print(f"{Fore.YELLOW}No data to export.{Style.RESET_ALL}")
                    return False
                
                # Get all possible keys from all reports
                fieldnames = set()
                for report in export_data:
                    fieldnames.update(report.keys())
                
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                    writer.writeheader()
                    writer.writerows(export_data)
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
    parser = argparse.ArgumentParser(description='IAM User Audit Tool')
    
    # Global options
    parser.add_argument('--profile', help='AWS profile to use')
    
    # Report options
    parser.add_argument('--user', help='Specific IAM user to audit')
    parser.add_argument('--full-report', action='store_true', help='Generate a full report of all users')
    parser.add_argument('--find-issues', action='store_true', help='Find users with security issues')
    parser.add_argument('--compliance-report', action='store_true', help='Generate a compliance report')
    
    # Output options
    parser.add_argument('--output-format', choices=['json', 'csv'], help='Output format for report export')
    parser.add_argument('--output-file', help='Output file path for report export')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create IAM user auditor
    auditor = IAMUserAuditor(profile=args.profile)
    
    # Generate user report
    user_reports = auditor.generate_user_report(user_name=args.user, find_issues=args.find_issues)
    
    # Display report based on options
    if args.compliance_report:
        compliance = auditor.generate_compliance_report(user_reports)
        auditor.display_compliance_report(compliance)
    elif args.find_issues:
        auditor.display_security_issues(user_reports)
    else:
        auditor.display_user_report(user_reports)
    
    # Export report if requested
    if args.output_format and args.output_file:
        auditor.export_report(user_reports, args.output_format, args.output_file)


if __name__ == '__main__':
    main()
