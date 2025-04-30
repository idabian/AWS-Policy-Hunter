# AWS Policy Hunter
**AWS Policy Hunter** is a powerful tool for security teams (red and blue alike) to visualize, inspect, and analyze AWS IAM relationships and risk posture using a Neo4j graph database.

## Overview
AWS Policy Hunter collects identity and permission data from AWS accounts, stores it as a graph in Neo4j, and analyzes relationships, policies, and misconfigurations to identify potential risks like privilege escalation, wildcard permissions, and trust policy flaws.

## Requirements
Make sure to use `pip` to install both `boto3` and `neo4j` libraries.

## Usage
TODO

## Features
- **Multiple identity types:** including users, groups, roles, instance profiles and accounts
- **Many relathionships:** including group memberships, role trusts, user access keys and more
- **IAM Policy analysis:** to detect dangerous policies that may result privilege escalation
- **Risk scoring:** is utilized to assess the risk of users, groups, roles and policies to the organization
- **Multi-account support:** allows for broader view of cross-account relationships in the organization

## Graph Components
### Nodes
- Account
- Policy
- User
- Group
- Role
- DeferatedIdentity
- Service
- EC2Instance
- Instance Profile
- AccessKey
- Global
### Relationships
- **MemberOf:** shows a membership relationship between a user and a group
- **HasAccessKey:** shows the access key used by a specific user
- **HasPolicy:** shows what policies (inline and managed) are linked to a user, group or role
- **HasRole:** shows what role is used by an instance profile
- **UsesProfile:** shows which EC2 instances use a specific instance profile
- **ContainsIdentity:** shows which account contains a user, group or role
- **CanAssume:** shows a trust between a role and an identity
- **MayAssume:** shows which policy allows its affected identity to assume a role
- **CanPassRole:** shows which policy allows to pass which role

## Disclaimer
This tool is intended **solely for use on AWS accounts that you own or have explicit permission to test**. Unauthorized access or scanning of accounts without consent is illegal and strictly prohibited. <br>
By using this tool, you agree to comply with all relevant laws and your organization's security policies. The authors are not responsible for misuse or any damage caused by this tool.

## License
MIT License <br>
Author: Idabian
