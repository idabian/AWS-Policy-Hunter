# AWS Policy Hunter
**AWS Policy Hunter** is a powerful tool for security teams (red and blue alike) to visualize, inspect, and analyze AWS IAM relationships and risk posture using a Neo4j graph database.

## Overview
AWS Policy Hunter collects identity and permission data from AWS accounts, stores it as a graph in Neo4j, and analyzes relationships, policies, and misconfigurations to identify potential risks like privilege escalation, wildcard permissions, and trust policy flaws.

## Features
- **Multiple identity types:** including users, groups, roles, instance profiles and accounts
- **Many relathionships:** including group memberships, role trusts, user access keys and more
- **IAM Policy analysis:** to detect dangerous policies that may result privilege escalation
- **Risk scoring:** is utilized to assess the risk of users, groups, roles and policies to the organization
- **Multi-account support:** allows for broader view of cross-account relationships in the organization
- **Built-in queries:** allow for easy work with the tool without knowing cypher syntax

## Requirements
Make sure to use `pip` to install both `boto3` and `neo4j` libraries.

## Usage
### Setup AWS Profile
Set the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables or set the `AWS_PROFILE` variable based on a profile in the `.aws/credentials` file. <br>
Using Bash:
```bash
export AWS_PROFILE=<profile-name>
```
Using CMD:
```bash
set AWS_PROFILE=<profile-name>
```
Using PowerShell:
```powershell
$env:AWS_PROFILE = "<profile-name>"
```
### Run the tool
Run the following to append data to the Neo4j database (useful for multi-account):
```bash
python aws_policy_hunter.py
```
Run the following to clear the Neo4j database and then collect data for clean output:
```bash
python aws_policy_hunter.py --clear
```
Run the following to change the credentials of the Neo4j database:
```bash
python aws_policy_hunter.py --credentials
```
### Interactive Mode
Since the tool does not have a graphical interface and relies on the Neo4j web browser (http://127.0.0.1:7474/ by default), this tool has an interactive mode that allows for multiple functionalities.
#### Start interactive mode
```bash
python aws_policy_hunter.py --interactive
```
#### Main commands
- `list`: lists all commands of the tool
- `clear_database`: clears the Neo4j database for clean scans
- `start_scan`: runs a regular scan (like running the tool without parameters)
- `set profile`: changes the AWS_PROFILE for multiple scans in different contexts
- `get profile`: shows the current AWS_PROFILE in use
- `set owned`: marks identities as owned based on ARN (useful for red team)
#### Queries
To visualize the information gathered by this tool, *cypher queries* are required to fetch data from the Neo4j database. <br>
This tool comes with 30 built in queries. It also provides adding and changing queries as well. <br>
Query commands:
- `query list`: shows indexed list of the saved queries
- `query get`: shows a specific (based on index) query to copy and paste in Neo4j web browser
- `query add`: adds a custom query to the saved queries

## Graph Components
For those who wish to create their own custom cypher queries, here are the nodes and relationships used in the graph.
### Nodes
- Account
- Policy
- User
- Group
- Role
- FederatedIdentity
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
