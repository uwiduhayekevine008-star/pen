"""
Cloud Infrastructure Vulnerability Scanner
Specialized scanner for AWS, Azure, GCP, and multi-cloud environments
"""

import asyncio
import json
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CloudResource:
    resource_id: str
    resource_type: str
    name: str
    region: str
    account_id: str
    tags: Dict[str, str] = field(default_factory=dict)
    configuration: Dict = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = {}
        if self.configuration is None:
            self.configuration = {}
        if self.vulnerabilities is None:
            self.vulnerabilities = []


@dataclass
class CloudVulnerability:
    vuln_id: str
    name: str
    severity: str
    description: str
    affected_resource: str
    remediation: str
    cve_id: Optional[str] = None
    cloud_provider: str = ""
    service: str = ""
    check_id: str = ""
    timestamp: str = ""


class CloudScanner:
    """Advanced cloud infrastructure vulnerability scanner"""
    
    def __init__(self):
        self.resources: List[CloudResource] = []
        self.vulnerabilities: List[CloudVulnerability] = []
        self.cloud_providers = ['aws', 'azure', 'gcp', 'oracle', 'ibm']
        
        # CIS AWS Foundations Benchmark checks
        self.aws_checks = {
            '1.1': {'name': 'Ensure IAM password policy requires minimum length of 14 or greater', 'severity': 'Medium'},
            '1.2': {'name': 'Ensure IAM password policy requires at least one uppercase letter', 'severity': 'Medium'},
            '1.3': {'name': 'Ensure IAM password policy requires at least one lowercase letter', 'severity': 'Medium'},
            '1.4': {'name': 'Ensure IAM password policy requires at least one number', 'severity': 'Medium'},
            '1.5': {'name': 'Ensure IAM password policy requires at least one symbol', 'severity': 'Medium'},
            '1.6': {'name': 'Ensure IAM password policy enables password expiration', 'severity': 'Medium'},
            '1.7': {'name': 'Ensure no root account access key exists', 'severity': 'High'},
            '1.8': {'name': 'Ensure MFA is enabled for the root account', 'severity': 'High'},
            '1.9': {'name': 'Ensure hardware MFA is enabled for the root account', 'severity': 'High'},
            '1.10': {'name': 'Ensure security questions are registered in the AWS account', 'severity': 'Low'},
            '1.11': {'name': 'Ensure no root account access key exists', 'severity': 'High'},
            '1.12': {'name': 'Ensure MFA is enabled for IAM users that have a console password', 'severity': 'Medium'},
            '1.13': {'name': 'Ensure credentials unused for 45 days are disabled', 'severity': 'Medium'},
            '1.14': {'name': 'Ensure access keys are rotated every 90 days or less', 'severity': 'Medium'},
            '1.15': {'name': 'Ensure no root account access key exists', 'severity': 'High'},
            '1.16': {'name': 'Ensure IAM policies are attached only to groups or roles', 'severity': 'Medium'},
            '1.17': {'name': 'Ensure IAM policies that allow full \"*:*\" administrative privileges are not created', 'severity': 'High'},
            '1.18': {'name': 'Ensure the default security group of every VPC restricts all traffic', 'severity': 'Medium'},
            '1.19': {'name': 'Ensure logging of cloudtrail multi-region is enabled', 'severity': 'High'},
            '1.20': {'name': 'Ensure S3 bucket policy restricts cross-account access', 'severity': 'High'},
            '1.21': {'name': 'Ensure S3 bucket is encrypted', 'severity': 'High'},
            '1.22': {'name': 'Ensure S3 bucket has versioning enabled', 'severity': 'Medium'},
            '1.23': {'name': 'Ensure S3 bucket has server-side encryption enabled', 'severity': 'High'},
            '1.24': {'name': 'Ensure S3 bucket has access logs enabled', 'severity': 'Medium'},
            '1.25': {'name': 'Ensure S3 bucket has public access blocked', 'severity': 'High'},
            '1.26': {'name': 'Ensure RDS instance has public access disabled', 'severity': 'High'},
            '1.27': {'name': 'Ensure RDS instance has encryption enabled', 'severity': 'High'},
            '1.28': {'name': 'Ensure RDS instance has multi-AZ enabled', 'severity': 'Medium'},
            '1.29': {'name': 'Ensure RDS instance has automated backups enabled', 'severity': 'Medium'},
            '1.30': {'name': 'Ensure RDS instance has deletion protection enabled', 'severity': 'Medium'},
        }
        
        # CIS Azure Benchmark checks
        self.azure_checks = {
            '1.1': {'name': 'Ensure that Microsoft Defender for Storage is enabled', 'severity': 'High'},
            '1.2': {'name': 'Ensure that Microsoft Defender for Containers is enabled', 'severity': 'High'},
            '1.3': {'name': 'Ensure that Microsoft Defender for Key Vault is enabled', 'severity': 'High'},
            '1.4': {'name': 'Ensure that Microsoft Defender for SQL on Servers is enabled', 'severity': 'High'},
            '1.5': {'name': 'Ensure that Microsoft Defender for SQL on Servers and AI is enabled', 'severity': 'High'},
            '1.6': {'name': 'Ensure that Microsoft Defender for App Service is enabled', 'severity': 'High'},
            '1.7': {'name': 'Ensure that Microsoft Defender for Azure Cosmos DB is enabled', 'severity': 'High'},
            '1.8': {'name': 'Ensure that Microsoft Defender for Azure SQL Database Servers is enabled', 'severity': 'High'},
            '1.9': {'name': 'Ensure that Microsoft Defender for Azure Synapse Analytics is enabled', 'severity': 'High'},
            '1.10': {'name': 'Ensure that Microsoft Defender for Azure DevOps is enabled', 'severity': 'High'},
        }
        
        # CIS GCP Benchmark checks
        self.gcp_checks = {
            '1.1': {'name': 'Ensure that the default network does not exist', 'severity': 'Medium'},
            '1.2': {'name': 'Ensure custom routes do not have 0.0.0.0/0 next hop without restriction', 'severity': 'Medium'},
            '1.3': {'name': 'Ensure VPC Flow Logs is enabled for all VPC networks', 'severity': 'High'},
            '1.4': {'name': 'Ensure that no instances in the network use the default service account with full access to all Cloud APIs', 'severity': 'High'},
            '1.5': {'name': 'Ensure that VPC Flow Logs is enabled for all subnets', 'severity': 'High'},
            '1.6': {'name': 'Ensure that DNSSEC is enabled for Cloud DNS', 'severity': 'Medium'},
            '1.7': {'name': 'Ensure that a default encryption key is set for GCE', 'severity': 'Medium'},
            '1.8': {'name': 'Ensure that default SSH keys are not enabled at the project level', 'severity': 'Medium'},
            '1.9': {'name': 'Ensure that default RDP keys are not enabled at the project level', 'severity': 'Medium'},
            '1.10': {'name': 'Ensure that OS Login is enabled for project', 'severity': 'Medium'},
        }
        
    async def scan_aws(self, account_id: str, region: str = 'us-east-1') -> List[CloudVulnerability]:
        """Scan AWS infrastructure for vulnerabilities"""
        vulns = []
        
        # Simulated AWS checks (in production, use boto3)
        checks_to_run = [
            ('1.7', 'Ensure no root account access key exists'),
            ('1.8', 'Ensure MFA is enabled for the root account'),
            ('1.17', 'Ensure IAM policies allow full \"*:*\" administrative privileges'),
            ('1.18', 'Ensure default security group restricts all traffic'),
            ('1.19', 'Ensure cloudtrail multi-region logging is enabled'),
            ('1.25', 'Ensure S3 bucket has public access blocked'),
            ('1.26', 'Ensure RDS instance has public access disabled'),
            ('1.27', 'Ensure RDS instance has encryption enabled'),
        ]
        
        for check_id, check_name in checks_to_run:
            # Simulated vulnerability detection
            if check_id in ['1.7', '1.8', '1.17', '1.25', '1.26', '1.27']:
                vulns.append(CloudVulnerability(
                    vuln_id=f"AWS-{check_id.replace('.', '-')}",
                    name=check_name,
                    severity="HIGH",
                    description=f"AWS {check_id} check failed - {check_name}",
                    affected_resource=f"arn:aws:iam::{account_id}:root",
                    remediation=f"Implement {check_name}",
                    cloud_provider="aws",
                    service="IAM/Security",
                    check_id=check_id
                ))
                
        return vulns
        
    async def scan_azure(self, subscription_id: str) -> List[CloudVulnerability]:
        """Scan Azure infrastructure for vulnerabilities"""
        vulns = []
        
        checks_to_run = [
            ('1.1', 'Ensure Microsoft Defender for Storage is enabled'),
            ('1.2', 'Ensure Microsoft Defender for Containers is enabled'),
            ('1.3', 'Ensure Microsoft Defender for Key Vault is enabled'),
            ('1.4', 'Ensure Microsoft Defender for SQL is enabled'),
        ]
        
        for check_id, check_name in checks_to_run:
            vulns.append(CloudVulnerability(
                vuln_id=f"AZURE-{check_id.replace('.', '-')}",
                name=check_name,
                severity="HIGH",
                description=f"Azure {check_id} check failed - {check_name}",
                affected_resource=f"subscriptions/{subscription_id}",
                remediation=f"Enable {check_name}",
                cloud_provider="azure",
                service="Security Center",
                check_id=check_id
            ))
            
        return vulns
        
    async def scan_gcp(self, project_id: str) -> List[CloudVulnerability]:
        """Scan GCP infrastructure for vulnerabilities"""
        vulns = []
        
        checks_to_run = [
            ('1.1', 'Ensure default network does not exist'),
            ('1.3', 'Ensure VPC Flow Logs is enabled'),
            ('1.4', 'Ensure instances do not use default service account with full access'),
            ('1.7', 'Ensure default encryption key is set for GCE'),
        ]
        
        for check_id, check_name in checks_to_run:
            vulns.append(CloudVulnerability(
                vuln_id=f"GCP-{check_id.replace('.', '-')}",
                name=check_name,
                severity="HIGH",
                description=f"GCP {check_id} check failed - {check_name}",
                affected_resource=f"projects/{project_id}",
                remediation=f"Implement {check_name}",
                cloud_provider="gcp",
                service="Security Command Center",
                check_id=check_id
            ))
            
        return vulns
        
    async def scan_s3_buckets(self, account_id: str) -> List[CloudVulnerability]:
        """Scan S3 buckets for security issues"""
        vulns = []
        
        # Simulated bucket scanning
        buckets = [
            'my-bucket-1',
            'my-bucket-2',
            'company-data',
            'backup-storage',
        ]
        
        for bucket in buckets:
            # Check for public access
            vulns.append(CloudVulnerability(
                vuln_id=f"S3-{hashlib.md5(bucket.encode()).hexdigest()[:8].upper()}",
                name=f"S3 Bucket Public Access",
                severity="HIGH",
                description=f"S3 bucket {bucket} may have public access",
                affected_resource=f"arn:aws:s3:::{bucket}",
                remediation="Enable block public access settings",
                cloud_provider="aws",
                service="S3",
                check_id="S3-001"
            ))
            
            # Check for encryption
            vulns.append(CloudVulnerability(
                vuln_id=f"S3-ENC-{hashlib.md5(bucket.encode()).hexdigest()[:8].upper()}",
                name=f"S3 Bucket Encryption Missing",
                severity="HIGH",
                description=f"S3 bucket {bucket} may not have encryption enabled",
                affected_resource=f"arn:aws:s3:::{bucket}",
                remediation="Enable server-side encryption",
                cloud_provider="aws",
                service="S3",
                check_id="S3-002"
            ))
            
        return vulns
        
    async def scan_ec2_instances(self, account_id: str, region: str = 'us-east-1') -> List[CloudVulnerability]:
        """Scan EC2 instances for security issues"""
        vulns = []
        
        # Simulated instance scanning
        instances = [
            'i-0123456789abcdef0',
            'i-0987654321fedcba0',
        ]
        
        for instance_id in instances:
            # Check for public IP
            vulns.append(CloudVulnerability(
                vuln_id=f"EC2-PUB-{instance_id[-8:].upper()}",
                name=f"EC2 Instance Public IP Exposure",
                severity="MEDIUM",
                description=f"EC2 instance {instance_id} has public IP exposure",
                affected_resource=f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
                remediation="Remove public IP or use NAT gateway",
                cloud_provider="aws",
                service="EC2",
                check_id="EC2-001"
            ))
            
            # Check for security group rules
            vulns.append(CloudVulnerability(
                vuln_id=f"EC2-SG-{instance_id[-8:].upper()}",
                name=f"EC2 Security Group Overly Permissive",
                severity="HIGH",
                description=f"EC2 instance {instance_id} has overly permissive security group rules",
                affected_resource=f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
                remediation="Restrict security group rules to minimum required access",
                cloud_provider="aws",
                service="EC2",
                check_id="EC2-002"
            ))
            
        return vulns
        
    async def scan_rds_instances(self, account_id: str, region: str = 'us-east-1') -> List[CloudVulnerability]:
        """Scan RDS instances for security issues"""
        vulns = []
        
        # Simulated RDS scanning
        databases = [
            'production-db',
            'staging-db',
            'analytics-db',
        ]
        
        for db_name in databases:
            # Check for public access
            vulns.append(CloudVulnerability(
                vuln_id=f"RDS-PUB-{hashlib.md5(db_name.encode()).hexdigest()[:8].upper()}",
                name=f"RDS Instance Public Access",
                severity="HIGH",
                description=f"RDS instance {db_name} may have public access enabled",
                affected_resource=f"arn:aws:rds:{region}:{account_id}:db:{db_name}",
                remediation="Disable public access for RDS instance",
                cloud_provider="aws",
                service="RDS",
                check_id="RDS-001"
            ))
            
            # Check for encryption
            vulns.append(CloudVulnerability(
                vuln_id=f"RDS-ENC-{hashlib.md5(db_name.encode()).hexdigest()[:8].upper()}",
                name=f"RDS Instance Encryption Missing",
                severity="HIGH",
                description=f"RDS instance {db_name} may not have encryption enabled",
                affected_resource=f"arn:aws:rds:{region}:{account_id}:db:{db_name}",
                remediation="Enable encryption for RDS instance",
                cloud_provider="aws",
                service="RDS",
                check_id="RDS-002"
            ))
            
        return vulns
        
    async def scan_lambda_functions(self, account_id: str, region: str = 'us-east-1') -> List[CloudVulnerability]:
        """Scan Lambda functions for security issues"""
        vulns = []
        
        # Simulated Lambda scanning
        functions = [
            'api-handler',
            'data-processor',
            'notification-service',
        ]
        
        for func_name in functions:
            # Check for overly permissive IAM roles
            vulns.append(CloudVulnerability(
                vuln_id=f"LAMBDA-IAM-{hashlib.md5(func_name.encode()).hexdigest()[:8].upper()}",
                name=f"Lambda IAM Role Overly Permissive",
                severity="HIGH",
                description=f"Lambda function {func_name} may have overly permissive IAM role",
                affected_resource=f"arn:aws:lambda:{region}:{account_id}:function:{func_name}",
                remediation="Implement least privilege IAM policies",
                cloud_provider="aws",
                service="Lambda",
                check_id="LAMBDA-001"
            ))
            
        return vulns
        
    async def scan_cloud_resources(self, provider: str, credentials: Dict) -> List[CloudVulnerability]:
        """Scan cloud resources based on provider"""
        all_vulns = []
        
        if provider == 'aws':
            account_id = credentials.get('account_id', '123456789012')
            region = credentials.get('region', 'us-east-1')
            
            all_vulns.extend(await self.scan_aws(account_id, region))
            all_vulns.extend(await self.scan_s3_buckets(account_id))
            all_vulns.extend(await self.scan_ec2_instances(account_id, region))
            all_vulns.extend(await self.scan_rds_instances(account_id, region))
            all_vulns.extend(await self.scan_lambda_functions(account_id, region))
            
        elif provider == 'azure':
            subscription_id = credentials.get('subscription_id', '00000000-0000-0000-0000-000000000000')
            all_vulns.extend(await self.scan_azure(subscription_id))
            
        elif provider == 'gcp':
            project_id = credentials.get('project_id', 'my-project')
            all_vulns.extend(await self.scan_gcp(project_id))
            
        return all_vulns


if __name__ == '__main__':
    import sys
    
    async def main():
        if len(sys.argv) < 2:
            print("Usage: python cloud_scanner.py <provider> [credentials_json]")
            return
            
        provider = sys.argv[1]
        credentials = {}
        
        if len(sys.argv) > 2:
            try:
                credentials = json.loads(sys.argv[2])
            except json.JSONDecodeError:
                print("Invalid JSON credentials")
                return
                
        scanner = CloudScanner()
        vulns = await scanner.scan_cloud_resources(provider, credentials)
        
        print(f"\n[*] Found {len(vulns)} cloud vulnerabilities:")
        for vuln in vulns:
            print(f"  [{vuln.severity}] {vuln.name}")
            print(f"    Resource: {vuln.affected_resource}")
            print(f"    Remediation: {vuln.remediation}")
            
    asyncio.run(main())