# AWS Policy Hunter
**AWS Policy Hunter** is a powerful tool for security teams (red and blue alike) to visualize, inspect, and analyze AWS IAM relationships and risk posture using a Neo4j graph database.

## Overview
AWS Policy Hunter collects identity and permission data from AWS accounts, stores it as a graph in Neo4j, and analyzes relationships, policies, and misconfigurations to identify potential risks like privilege escalation, wildcard permissions, and trust policy flaws.

## Requirements
Make sure to use `pip` to install both `boto3` and `neo4j` libraries.

## Usage
TODO

## Features
- Multiple identity types including users, groups, roles, instance profiles and accounts
- Many relathionships including group memberships, role trusts, user access keys and more
- IAM Policy analysis to detect dangerous policies that may result privilege escalation
- Risk scoring is utilized to assess the risk of users, groups, roles and policies to the organization
- Multi-account support allows for broader view of cross-account relationships in the organization

## Graph Components
TODO

## Disclaimer
This tool is intended **solely for use on AWS accounts that you own or have explicit permission to test**. Unauthorized access or scanning of accounts without consent is illegal and strictly prohibited. <br>
By using this tool, you agree to comply with all relevant laws and your organization's security policies. The authors are not responsible for misuse or any damage caused by this tool.

## License
MIT License <br>
Author: Idabian
