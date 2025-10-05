# AWS Swiss Army Toolkit

A comprehensive collection of Python and Bash automation scripts for AWS resource management, monitoring, security, cost optimization, backup & recovery, and networking.

**Authored by V Vier**

## Overview

The AWS Swiss Army Toolkit provides DevOps engineers, cloud administrators, and developers with ready-to-use scripts for common AWS tasks and automation scenarios. These tools help streamline AWS operations, enhance security posture, optimize costs, and implement best practices.

## Categories

The toolkit is organized into the following categories:

1. **Resource Management**
   - Scripts for creating, updating, and deleting AWS resources
   - Automation for resource provisioning and cleanup
   - Inventory and tagging tools

2. **Monitoring**
   - CloudWatch metric collection and analysis
   - Custom monitoring solutions
   - Alerting and notification scripts

3. **Security**
   - IAM user and role auditing
   - Security group and NACL analysis
   - Compliance checking and reporting

4. **Cost Optimization**
   - Resource utilization analysis
   - Cost anomaly detection
   - Reserved instance and savings plan recommendations

5. **Backup & Recovery**
   - Automated backup solutions
   - Cross-region replication tools
   - Disaster recovery automation

6. **Networking**
   - VPC configuration and analysis
   - Route table and subnet management
   - DNS and Route 53 automation

## Prerequisites

- Python 3.6+
- AWS CLI v2
- Boto3 (AWS SDK for Python)
- AWS credentials configured (`~/.aws/credentials` or environment variables)
- Bash shell (for shell scripts)

## Installation

```bash
# Clone the repository
git clone https://github.com/v-vier/aws-toolkit.git

# Install required Python packages
cd aws-toolkit
pip install -r requirements.txt

# Make shell scripts executable
chmod +x *.sh
```

## Usage

Each script includes detailed documentation and usage examples. Generally, scripts can be run as follows:

**Python scripts:**
```bash
python3 script_name.py [arguments]
```

**Bash scripts:**
```bash
./script_name.sh [arguments]
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- AWS Documentation and Sample Code
- AWS CLI and SDK Teams
- AWS Community Builders and Heroes
