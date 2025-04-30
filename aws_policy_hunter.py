from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from neo4j import GraphDatabase
from threading import Lock
import boto3
import botocore.exceptions
import time
import argparse
import json
import os

# Retry wrapper for AWS throttling:
def with_retries(func, max_retries=5, delay=1):
    def wrapper(*args, **kwargs):
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except botocore.exceptions.ClientError as e:
                code = e.response['Error']['Code']
                if code in ['Throttling', 'ThrottlingException', 'RequestLimitExceeded']:
                    time.sleep(delay * (2 ** attempt))
                else:
                    raise
        raise Exception(f"Max retries exceeded for {func.__name__}")
    return wrapper

# AWS interaction:
iam = boto3.client('iam')
sts = boto3.client('sts')
ec2 = boto3.client('ec2', region_name='us-east-1')

# Neo4j connection:
driver = None
def connect_to_neo4j(config):
    # VERY IMPORTANT
    global driver
    # Fetch creds from config:
    NEO4J_URI = config['Credentials']['Uri']
    NEO4J_USER = config['Credentials']['Username']
    NEO4J_PASS = config['Credentials']['Password']
    # Connect to the database:
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

# Threading locks:
policy_cache_lock = Lock()
arn_set_lock = Lock()

# Command help and listing:
command_help = {
    "help": {
        "Syntax": "help [command]",
        "Description": "Shows this help menu.\nIf adding specific command it will only list help for it."
    },
    "exit": {
        "Syntax": "exit",
        "Description": "Exits the shell (same as 'quit')."
    },
    "quit": {
        "Syntax": "quit",
        "Description": "Quits the shell (same as 'exit')."
    },
    "list": {
        "Syntax": "list",
        "Description": "Lists all available commands."
    },
    "clear_database": {
        "Syntax": "clear_database",
        "Description": "Clears the Neo4j database to make it empty."
    },
    "start_scan": {
        "Syntax": "start_scan [clear]",
        "Description": "Starts a scan and analysis (like when executing it in non-interactive mode).\nParameters:\n  - clear: Clears the database before scan"
    },
    "query": {
        "Syntax": "query {list|add|set|get|delete} [index]",
        "Description": "Used to manage queries for the Neo4j shell.\nParameters:\n  - list: gives indexed list of all queries\n  - add: adds a new custom query\n  - set [index]: modifies an existing query\n  - get [index]: shows the [index]th query for copying\n  - delete [index]: remove the [index]th query"
    },
    "set": {
        "Syntax": "set {env|profile|credentials|owned} [*params]",
        "Description": "Used to set different settings. For more information type 'help set {keyword}'."
    },
    "set env": {
        "Syntax": "set env {variable} {value}",
        "Description": "Used to set environment variables such as AWS credentials."
    },
    "set profile": {
        "Syntax": "set profile {name}",
        "Description": "Modifies the profile from the '.aws/credentials' file to be used."
    },
    "set credentials": {
        "Syntax": "set credentials",
        "Description": "Change the Neo4j credentials in the configuration file. A restart of the program is required after using this command."
    },
    "set owned": {
        "Syntax": "set owned {arn} {true|false}",
        "Description": "Add or remove 'owned' mark to an identity if compromised based on ARN.\nParameters:\n  - arn: the ARN of the identity\n  - true|false: the static value to set"
    },
    "get": {
        "Syntax": "get {profile|credentials} [cleartext]",
        "Description": "Get the AWS profile or Neo4j credentials. Add 'cleartext' to show Neo4j password."
    }
}

#########################
#                       #
#    Neo4J Functions    #
#                       #
#########################

# Delete database content for fresh start:
def clear_graph(tx):
    tx.run("MATCH (n) DETACH DELETE n")

# Create account node:
def create_account(tx, account_id, arn):
    tx.run("""
        MERGE (a:Account {id: $account_id})
        SET a.arn = $arn
    """, account_id=account_id, arn=arn)

# Create user node:
def create_user(tx, user, has_mfa, has_login_profile, access_key_count, account_id):
    tx.run("""
        MERGE (u:User {arn: $arn})
        SET u.name = $name,
            u.createDate = $createDate,
            u.path = $path,
            u.hasMFA = $hasMFA,
            u.hasLoginProfile = $hasLoginProfile,
            u.accessKeyCount = $accessKeyCount,
            u.accountId = $accountId
    """, name=user['UserName'], arn=user['Arn'],
         createDate=str(user['CreateDate']), path=user['Path'],
         hasMFA=has_mfa, hasLoginProfile=has_login_profile,
         accessKeyCount=access_key_count, accountId=account_id)

# Create group node:
def create_group(tx, group, account_id):
    tx.run("""
        MERGE (g:Group {arn: $arn})
        SET g.name = $name,
            g.createDate = $createDate,
            g.path = $path,
            g.accountId = $accountId
    """, name=group['GroupName'], arn=group['Arn'],
         createDate=str(group['CreateDate']), path=group['Path'], accountId=account_id)

# Create role node:
def create_role(tx, role, account_id):
    tx.run("""
        MERGE (r:Role {arn: $arn})
        SET r.name = $name,
            r.createDate = $createDate,
            r.path = $path,
            r.maxSessionDuration = $maxSessionDuration,
            r.accountId = $accountId
    """, name=role['RoleName'], arn=role['Arn'],
         createDate=str(role['CreateDate']), path=role['Path'],
         maxSessionDuration=role['MaxSessionDuration'], accountId=account_id)

# Create service node:
def create_service_node(tx, service_name):
    tx.run("""
        MERGE (s:Service {name: $name})
        SET s.type = 'Service'
    """, name=service_name)

# Create federated identity node:
def create_federated_node(tx, provider_arn):
    tx.run("""
        MERGE (f:FederatedIdentity {arn: $arn})
        SET f.provider = $provider,
            f.type = 'Federated'
    """, arn=provider_arn, provider=provider_arn.split('/')[-1])

# Create policy node:
def create_policy(tx, policy_arn, policy_name):
    tx.run("""
        MERGE (p:Policy {arn: $arn})
        ON CREATE SET p.name = $name
    """, arn=policy_arn, name=policy_name)

# Create group membership link:
def create_membership(tx, user_arn, group_arn):
    tx.run("""
        MATCH (u:User {arn: $user_arn}), (g:Group {arn: $group_arn})
        MERGE (u)-[:MemberOf]->(g)
    """, user_arn=user_arn, group_arn=group_arn)

# Create policy usage link:
def create_has_policy(tx, entity_type, entity_arn, policy_arn):
    tx.run(f"""
        MATCH (e:{entity_type} {{arn: $entity_arn}}), (p:Policy {{arn: $policy_arn}})
        MERGE (e)-[:HasPolicy]->(p)
    """, entity_arn=entity_arn, policy_arn=policy_arn)

# Create access key node:
def create_access_key_node(tx, access_key):
    tx.run("""
        MERGE (k:AccessKey {accessKeyId: $accessKeyId})
        SET k.status = $status,
            k.createDate = $createDate,
            k.ageDays = $ageDays,
            k.lastUsedDate = $lastUsedDate
    """, accessKeyId=access_key['accessKeyId'],
         status=access_key['status'],
         createDate=access_key['createDate'],
         ageDays=access_key['ageDays'],
         lastUsedDate=access_key['lastUsedDate'])

# Create instance profile node:
def create_instance_profile(tx, profile):
    tx.run("""
        MERGE (p:InstanceProfile {arn: $arn})
        SET p.name = $name,
            p.path = $path,
            p.createDate = $createDate,
            p.accountId = $accountId
    """, arn=profile['Arn'], name=profile['InstanceProfileName'],
         path=profile['Path'], createDate=str(profile['CreateDate']),
         accountId=profile['Arn'].split(':')[4])

# Create profile-role relationship:
def create_profile_role_relationship(tx, profile_arn, role_arn):
    tx.run("""
        MATCH (p:InstanceProfile {arn: $profile_arn})
        MATCH (r:Role {arn: $role_arn})
        MERGE (p)-[:HasRole]->(r)
    """, profile_arn=profile_arn, role_arn=role_arn)

# Create EC2 node:
def create_ec2_instance(tx, instance, region):
    tx.run("""
        MERGE (i:EC2Instance {instanceId: $instanceId})
        SET i.name = $name,
            i.launchTime = $launchTime,
            i.state = $state,
            i.type = $type,
            i.vpcId = $vpcId,
            i.subnetId = $subnetId,
            i.publicIp = $publicIp,
            i.privateIp = $privateIp,
            i.region = $region
    """, instanceId=instance['InstanceId'],
         name=instance.get('Name'),
         launchTime=str(instance['LaunchTime']),
         state=instance['State']['Name'],
         type=instance['InstanceType'],
         vpcId=instance.get('VpcId'),
         subnetId=instance.get('SubnetId'),
         publicIp=instance.get('PublicIpAddress'),
         privateIp=instance.get('PrivateIpAddress'),
         region=region)

# Create ec2-profile link:
def create_instance_profile_link(tx, instance_id, profile_arn):
    tx.run("""
        MATCH (i:EC2Instance {instanceId: $instance_id})
        MATCH (p:InstanceProfile {arn: $profile_arn})
        MERGE (i)-[:UsesProfile]->(p)
    """, instance_id=instance_id, profile_arn=profile_arn)

# Create user-access key relationship:
def create_access_key_relationship(tx, user_arn, access_key_id):
    tx.run("""
        MATCH (u:User {arn: $user_arn}), (k:AccessKey {accessKeyId: $access_key_id})
        MERGE (u)-[:HasAccessKey]->(k)
    """, user_arn=user_arn, access_key_id=access_key_id)

# Create identity-account link:
def create_identity_membership(tx, account_id, identity_type, identity_arn):
    tx.run(f"""
        MATCH (a:Account {{id: $account_id}}), (i:{identity_type} {{arn: $identity_arn}})
        MERGE (a)-[:ContainsIdentity]->(i)
    """, account_id=account_id, identity_arn=identity_arn)

# Create identity-role assume link:
def create_can_assume(tx, source_label, source_key, source_value, target_role_arn):
    tx.run(f"""
        MATCH (src:{source_label} {{{source_key}: $source_value}}),
              (role:Role {{arn: $role_arn}})
        MERGE (src)-[:CanAssume]->(role)
    """, source_value=source_value, role_arn=target_role_arn)

# Create account-role assume link:
def create_account_trust(tx, account_id, target_role_arn):
    tx.run("""
        MERGE (a:Account {id: $account_id})
            ON CREATE SET a.arn = 'arn:aws:iam::' + $account_id + ':root', a.external = true
        WITH a
        MATCH (r:Role {arn: $role_arn})
        MERGE (a)-[:CanAssume]->(r)
        SET r.crossAccount = true
    """, account_id=account_id, role_arn=target_role_arn)

# Create external identity nodes:
def create_stub_iam_identity(tx, arn):
    # Select node type:
    if ":user/" in arn:
        label = "User"
    elif ":group/" in arn:
        label = "Group"
    elif ":role/" in arn:
        label = "Role"
    else:
        return

    # Create properties for all identities:
    account_id = arn.split(":")[4]
    props = {
        "name": arn.split("/")[-1],
        "accountId": account_id,
        "external": True
    }

    # Add default maxSessionDuration for roles:
    if label == "Role":
        props["maxSessionDuration"] = 3600
    set_clause = ", ".join([f"i.{k} = ${k}" for k in props])

    # Actually writing stuff to Neo4j:
    query = f"""
        MERGE (a:Account {{id: $accountId}})
            ON CREATE SET a.arn = 'arn:aws:iam::' + $accountId + ':root', a.external = true
        MERGE (i:{label} {{arn: $arn}})
            ON CREATE SET {set_clause}
        MERGE (a)-[:ContainsIdentity]->(i)
    """
    tx.run(query, arn=arn, **props)

# Create global node:
def create_global_node(tx):
    tx.run("""
        MERGE (g:Global {name: "*"})
        ON CREATE SET g.owned = true
    """)

# Add external id to role node:
def set_external_id_on_role(tx, role_arn, external_ids):
    tx.run("""
        MATCH (r:Role {arn: $role_arn})
        SET r.externalId = $external_ids
    """, role_arn=role_arn, external_ids=external_ids)

# Add global-role link on NotPrincipal statement:
def create_may_assume_global(tx, target_role_arn):
    tx.run("""
        MATCH (g:Global {name: "*"})
        MATCH (r:Role {arn: $role_arn})
        MERGE (g)-[:MayAssume]->(r)
    """, role_arn=target_role_arn)

# Set ownership for identity:
def set_ownership_for_identity(tx, arn, value):
    tx.run("""
        MATCH (i {arn: $arn})
        SET i.owned = $value
    """, arn=arn, value=value)

#######################
#                     #
#    IAM Functions    #
#                     #
#######################

# Handle pagination for large organizations:
def paginate_list(api_func, key):
    paginator = iam.get_paginator(api_func)
    results = []
    for page in paginator.paginate():
        results.extend(page[key])
    return results

# Get all users and groups:
def list_users_and_groups():
    print("Fetching IAM users.")
    users = paginate_list('list_users', 'Users')
    print("Fetching IAM groups.")
    groups = paginate_list('list_groups', 'Groups')
    return users, groups

# Get all roles:
def list_roles():
    print("Fetching IAM roles.")
    return paginate_list('list_roles', 'Roles')

# Get group memberships for a user:
def get_user_groups(user_name):
    return iam.list_groups_for_user(UserName=user_name)['Groups']

# Get inline and attached policies for user:
def get_user_policies(user_name):
    inline = iam.list_user_policies(UserName=user_name)['PolicyNames']
    attached = []
    paginator = iam.get_paginator('list_attached_user_policies')
    for page in paginator.paginate(UserName=user_name):
        attached.extend(page['AttachedPolicies'])
    return inline, attached

# Get inline and attached policies for group:
def get_group_policies(group_name):
    inline = iam.list_group_policies(GroupName=group_name)['PolicyNames']
    attached = []
    paginator = iam.get_paginator('list_attached_group_policies')
    for page in paginator.paginate(GroupName=group_name):
        attached.extend(page['AttachedPolicies'])
    return inline, attached

# Get inline and attached policies for role:
def get_role_policies(role_name):
    inline = iam.list_role_policies(RoleName=role_name)['PolicyNames']
    attached = []
    paginator = iam.get_paginator('list_attached_role_policies')
    for page in paginator.paginate(RoleName=role_name):
        attached.extend(page['AttachedPolicies'])
    return inline, attached

# Check MFA and web console password for a user:
@with_retries
def get_mfa_and_login_status(user_name):
    has_mfa = bool(iam.list_mfa_devices(UserName=user_name)['MFADevices'])
    try:
        iam.get_login_profile(UserName=user_name)
        has_login_profile = True
    except iam.exceptions.NoSuchEntityException:
        has_login_profile = False
    return has_mfa, has_login_profile

# Get access keys for a user:
@with_retries
def get_access_keys(user_name):
    keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
    result = []
    for k in keys:
        access_key_id = k['AccessKeyId']
        create_date = k['CreateDate']
        age_days = (datetime.now(timezone.utc) - create_date).days
        try:
            last_used_resp = iam.get_access_key_last_used(AccessKeyId=access_key_id)
            last_used_date = last_used_resp['AccessKeyLastUsed'].get('LastUsedDate')
        except Exception:
            last_used_date = None
        result.append({
            'userName': user_name,
            'accessKeyId': access_key_id,
            'status': k['Status'],
            'createDate': str(create_date),
            'ageDays': age_days,
            'lastUsedDate': str(last_used_date) if last_used_date else None
        })
    return result

# Handle trust policy parsing for roles:
def get_trust_principals_from_assume_role_policy(policy_doc):
    principals = []
    statements = policy_doc.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if stmt.get('Effect') != 'Allow':
            continue
        principal = stmt.get('Principal')
        if not principal:
            continue
        # Service Principal
        if 'Service' in principal:
            services = principal['Service']
            if isinstance(services, str):
                services = [services]
            principals.extend(('Service', s) for s in services)
        # Federated Principal
        if 'Federated' in principal:
            federated = principal['Federated']
            if isinstance(federated, str):
                federated = [federated]
            principals.extend(('Federated', f) for f in federated)
        # IAM Principal (User/Role/Group or Account)
        if 'AWS' in principal:
            aws_principals = principal['AWS']
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for aws in aws_principals:
                if aws.startswith("arn:aws:iam::"):
                    if aws.endswith(":root"):
                        account_id = aws.split(":")[4]
                        if account_id == "*":
                            principals.append(('Global', '*'))
                        else:
                            principals.append(('Account', account_id))
                    else:
                        principals.append(('IAM', aws))
                elif aws == "*":
                    principals.append(('Global', '*'))
                elif aws.isdigit() and len(aws) == 12:
                    principals.append(('Account', aws))

    return principals

# Handle EC2 instances:
@with_retries
def process_ec2_instances(region, session):
    print(f"Processing EC2 region: {region}".ljust(100), end="\r")
    ec2 = boto3.client('ec2', region_name=region)
    paginator = ec2.get_paginator('describe_instances')

    for page in paginator.paginate():
        for reservation in page['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                print(f"EC2 Instance: {instance_id}".ljust(100), end="\r")

                # Extract 'Name' tag:
                name = None
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        name = tag['Value']
                        break
                instance['Name'] = name

                session.execute_write(create_ec2_instance, instance, region)

                if 'IamInstanceProfile' in instance:
                    profile_arn = instance['IamInstanceProfile']['Arn']
                    session.execute_write(create_instance_profile_link, instance_id, profile_arn)

########################
#                      #
#    Parallel Magic    #
#                      #
########################

# Handling users:
def process_user(user, account_id):
    user_name = user['UserName']
    user_arn = user['Arn']
    print(f"User: {user_name}".ljust(100), end="\r")
    has_mfa, has_login_profile = get_mfa_and_login_status(user_name)
    access_keys = get_access_keys(user_name)
    access_key_count = len(access_keys)

    with driver.session() as session:
        session.execute_write(create_user, user, has_mfa, has_login_profile, access_key_count, account_id)
        session.execute_write(create_identity_membership, account_id, "User", user_arn)
        for key in access_keys:
            session.execute_write(create_access_key_node, key)
            session.execute_write(create_access_key_relationship, user_arn, key['accessKeyId'])

def process_users_parallel(users, account_id, max_workers=15):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(lambda u: process_user(u, account_id), users)

# Handling user group membeships and policies:
@with_retries
def process_user_links(user, account_id):
    user_name = user['UserName']
    user_arn = user['Arn']
    print(f"User: {user_name}".ljust(100), end="\r")

    # IAM API calls
    groups = get_user_groups(user_name)
    inline, attached = get_user_policies(user_name)

    with driver.session() as session:
        # Memberships
        for group in groups:
            session.execute_write(create_membership, user_arn, group['Arn'])

        # Inline Policies
        for name in inline:
            policy_arn = f"inline-user:{user_arn.split(':')[4]}:{user_name}/{name}"
            session.execute_write(create_policy, policy_arn, name)
            session.execute_write(create_has_policy, "User", user_arn, policy_arn)

        # Managed Policies
        for policy in attached:
            session.execute_write(create_policy, policy['PolicyArn'], policy['PolicyName'])
            session.execute_write(create_has_policy, "User", user_arn, policy['PolicyArn'])

def process_user_links_parallel(users, account_id, max_workers=15):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(lambda u: process_user_links(u, account_id), users)

# Handle group policies:
@with_retries
def process_group_policies(group, account_id):
    group_name = group['GroupName']
    group_arn = group['Arn']
    print(f"Group: {group_name}".ljust(100), end="\r")

    inline, attached = get_group_policies(group_name)

    with driver.session() as session:
        # Inline
        for name in inline:
            policy_arn = f"inline-group:{group_arn.split(':')[4]}:{group_name}/{name}"
            session.execute_write(create_policy, policy_arn, name)
            session.execute_write(create_has_policy, "Group", group_arn, policy_arn)

        # Managed
        for policy in attached:
            session.execute_write(create_policy, policy['PolicyArn'], policy['PolicyName'])
            session.execute_write(create_has_policy, "Group", group_arn, policy['PolicyArn'])

def process_group_policies_parallel(groups, account_id, max_workers=15):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(lambda g: process_group_policies(g, account_id), groups)

# Handle role policies:
@with_retries
def process_role_policies(role, account_id):
    role_name = role['RoleName']
    role_arn = role['Arn']
    print(f"Role: {role_name}".ljust(100), end="\r")

    inline, attached = get_role_policies(role_name)

    with driver.session() as session:
        session.execute_write(create_identity_membership, account_id, "Role", role_arn)

        for name in inline:
            policy_arn = f"inline-role:{role_arn.split(':')[4]}:{role_name}/{name}"
            session.execute_write(create_policy, policy_arn, name)
            session.execute_write(create_has_policy, "Role", role_arn, policy_arn)

        for policy in attached:
            session.execute_write(create_policy, policy['PolicyArn'], policy['PolicyName'])
            session.execute_write(create_has_policy, "Role", role_arn, policy['PolicyArn'])

def process_role_policies_parallel(roles, account_id, max_workers=15):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(lambda r: process_role_policies(r, account_id), roles)

# Handle EC2 regions:
def process_ec2_parallel(regions):
    with ThreadPoolExecutor(max_workers=15) as executor:
        executor.map(lambda region: run_ec2_with_session(region), regions)

def run_ec2_with_session(region):
    with driver.session() as session:
        process_ec2_instances(region, session)

###############################
#                             #
#    Policy Cache Handling    #
#                             #
###############################

# Fetch a single managed policy:
@with_retries
def fetch_managed_policy(arn):
    metadata = iam.get_policy(PolicyArn=arn)['Policy']
    version_id = metadata['DefaultVersionId']
    version = iam.get_policy_version(
        PolicyArn=arn,
        VersionId=version_id
    )['PolicyVersion']
    return {
        'Document': version['Document'],
        'VersionId': version_id,
        'Source': 'Managed'
    }

# Fetch a single inline policy from identity:
@with_retries
def fetch_inline_policy(user_type, name, policy_name):
    if user_type == 'User':
        result = iam.get_user_policy(UserName=name, PolicyName=policy_name)
    elif user_type == 'Group':
        result = iam.get_group_policy(GroupName=name, PolicyName=policy_name)
    elif user_type == 'Role':
        result = iam.get_role_policy(RoleName=name, PolicyName=policy_name)
    else:
        return None
    return {
        'Document': result['PolicyDocument'],
        'VersionId': None,
        'Source': 'Inline'
    }

# Handle managed and inline policies for a single user:
def deep_process_user_policies(user, policy_cache, managed_policy_arns):
    user_name = user['UserName']
    user_arn = user['Arn']
    print(f"User: {user_name}".ljust(100), end="\r")
    inline = iam.list_user_policies(UserName=user_name)['PolicyNames']
    for policy_name in inline:
        key = f"inline-user:{user_arn.split(':')[4]}:{user_name}/{policy_name}"
        result = fetch_inline_policy('User', user_name, policy_name)
        with policy_cache_lock:
            policy_cache[key] = result

    attached = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
    with arn_set_lock:
        for policy in attached:
            managed_policy_arns.add(policy['PolicyArn'])

# Handle managed and inline policies for a single group:
def deep_process_group_policies(group, policy_cache, managed_policy_arns):
    group_name = group['GroupName']
    group_arn = group['Arn']
    print(f"Group: {group_name}".ljust(100), end="\r")
    inline = iam.list_group_policies(GroupName=group_name)['PolicyNames']
    for policy_name in inline:
        key = f"inline-group:{group_arn.split(':')[4]}:{group_name}/{policy_name}"
        result = fetch_inline_policy('Group', group_name, policy_name)
        with policy_cache_lock:
            policy_cache[key] = result

    attached = iam.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
    with arn_set_lock:
        for policy in attached:
            managed_policy_arns.add(policy['PolicyArn'])

# Handle managed and inline policies for a single role:
def deep_process_role_policies(role, policy_cache, managed_policy_arns):
    role_name = role['RoleName']
    role_arn = role['Arn']
    print(f"Role: {role_name}".ljust(100), end="\r")
    inline = iam.list_role_policies(RoleName=role_name)['PolicyNames']
    for policy_name in inline:
        key = f"inline-role:{role_arn.split(':')[4]}:{role_name}/{policy_name}"
        result = fetch_inline_policy('Role', role_name, policy_name)
        with policy_cache_lock:
            policy_cache[key] = result

    attached = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    with arn_set_lock:
        for policy in attached:
            managed_policy_arns.add(policy['PolicyArn'])

# Create chache pool of all policies for all identities:
def build_policy_cache_parallel(users, groups, roles, max_workers=15):
    policy_cache = {}
    managed_policy_arns = set()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit identity policy gatherers:
        for user in users:
            executor.submit(deep_process_user_policies, user, policy_cache, managed_policy_arns)
        for group in groups:
            executor.submit(deep_process_group_policies, group, policy_cache, managed_policy_arns)
        for role in roles:
            executor.submit(deep_process_role_policies, role, policy_cache, managed_policy_arns)

        executor.shutdown(wait=True)

    # Fetch managed policies in parallel:
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_arn = {
            executor.submit(fetch_managed_policy, arn): arn
            for arn in managed_policy_arns
        }

        for future in as_completed(future_to_arn):
            arn = future_to_arn[future]
            try:
                result = future.result()
                with policy_cache_lock:
                    policy_cache[arn] = result
            except Exception as e:
                print(f"[!] Failed to fetch managed policy {arn}: {e}")

    return policy_cache

################################
#                              #
#    Policy Cache Analyzing    #
#                              #
################################

# Test for conditional statements in policy:
def analyze_conditions(stmt, results):
    if "Condition" in stmt:
        results["conditional"] = True

# Test for wildcard in actions and resources in policy:
def analyze_wildcards(stmt, results):
    # Skip statement if not allow:
    if stmt.get("Effect") != "Allow":
        return
    # Helper function to detect wildcard:
    def contains_wildcard(value):
        if isinstance(value, str):
            return value.strip() == "*"
        if isinstance(value, list):
            return "*" in [v.strip() for v in value]
        return False
    # Test action for wildcard:
    if contains_wildcard(stmt.get("Action")):
        results["flags"].add("hasWildcardAction")
    # Test resource for wildcard:
    if contains_wildcard(stmt.get("Resource")):
        results["flags"].add("hasWildcardResource")

# Test if statement permits admin access (any-any):
def analyze_admin_access(stmt, results):
    # Skip statement if not allow:
    if stmt.get("Effect") != "Allow":
        return
    # Force actions and resources into lists:
    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    resources = stmt.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]
    # Validate statement:
    if "*" in actions and "*" in resources:
        results["flags"].add("hasAdminAccess")

# Test for blacklist staements:
def analyze_blacklists(stmt, results):
    if stmt.get("Effect") != "Allow":
        return
    if "NotAction" in stmt:
        results["flags"].add("blacklistAction")
    if "NotResource" in stmt:
        results["flags"].add("blacklistResource")
    if "NotPrincipal" in stmt:
        results["flags"].add("blacklistPrincipal")

# Test for service wildcards in policy statements:
def analyze_service_wildcards(stmt, results):
    # Skip statement if not allow:
    if stmt.get("Effect") != "Allow":
        return
    # Make sure actions are list:
    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    # Loop through the actions to find services:
    for action in actions:
        if isinstance(action, str) and action.endswith(":*"):
            service = action.split(":")[0].strip()
            if service:
                results["services"].add(f"{service}.amazonaws.com")

# Test for 'sts:AssumeRole' in policies to add MayAssume links:
def analyze_sts_assume(stmt, results):
    # Skip statement if not allow:
    if stmt.get("Effect") != "Allow":
        return
    # Make sure actions are list:
    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    # Skip statement if not assume role:
    if "sts:AssumeRole" not in actions and not any(a.strip() == "sts:AssumeRole" for a in actions):
        return
    # Make sure resources are list:
    resources = stmt.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]
    # Add resources to set for parsing later:
    for res in resources:
        if res.strip() == "*":
            results["may_assume_roles"].add("*")
        elif ":role/" in res:
            results["may_assume_roles"].add(res.strip())

# Test for 'iam:PassRole' in policies to add links for services:
def analyze_pass_role(stmt, results):
    # Skip statement if not allow:
    if stmt.get("Effect") != "Allow":
        return
    # Make sure actions are list:
    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    # Skip statement if not pass role:
    if "iam:PassRole" not in actions and not any(a.strip() == "iam:PassRole" for a in actions):
        return
    # Make sure resources are list:
    resources = stmt.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]
    # Add resources to set for parsing later:
    for res in resources:
        if res.strip() == "*":
            results["pass_roles"].add("*")
        elif ":role/" in res:
            results["pass_roles"].add(res.strip())

# Calculate risk score for policies:
def calculate_risk_score_from_flags(results):
    # Scoring weights:
    weights = {
        "hasAdminAccess": 100,
        "hasWildcardAction": 40,
        "hasWildcardResource": 30,
        "blacklistAction": 30,
        "blacklistResource": 30,
        "blacklistPrincipal": 20,
        "MayAssume": 20,
        "CanPassRole": 20,
        "conditional": -20
    }

    # Calculate raw score:
    score = 0
    for flag in results["flags"]:
        score += weights.get(flag, 0)
    if results["conditional"]:
        score += weights["conditional"]

    # Normalize score to be 0–100:
    return max(0, min(score, 100))

# Handle updates to Neo4j based on deep inspection:
def apply_policy_analysis_to_neo4j(tx, policy_arn, results, version=None):
    # Calculate risk for policy:
    score = calculate_risk_score_from_flags(results)

    # Set basic properties on the policy node:
    set_flags = ", ".join([f"p.{flag} = true" for flag in results["flags"]])
    conditional = "p.conditional = true" if results["conditional"] else ""
    version_set = f"p.versionId = $version" if version else ""
    score_set = "p.riskScore = $score"

    properties_clause = ", ".join(filter(None, [set_flags, conditional, version_set, score_set]))
    if properties_clause:
        tx.run(f"""
            MATCH (p:Policy {{arn: $arn}})
            SET {properties_clause}
        """, arn=policy_arn, version=version, score=score)

    # Link to services:
    for service in results["services"]:
        tx.run("""
            MERGE (s:Service {name: $service})
            WITH s
            MATCH (p:Policy {arn: $arn})
            MERGE (p)-[:HasFullControl]->(s)
        """, service=service, arn=policy_arn)

    # Link to roles (MayAssume):
    for role_arn in results["may_assume_roles"]:
        if role_arn == "*":
            tx.run("""
                MATCH (p:Policy {arn: $arn}), (g:Global {name: "*"})
                MERGE (p)-[:MayAssume]->(g)
            """, arn=policy_arn)
        else:
            tx.run("""
                MERGE (r:Role {arn: $role_arn})
                    ON CREATE SET r.name = split($role_arn, '/')[1],
                                  r.accountId = split($role_arn, ':')[4],
                                  r.maxSessionDuration = 3600,
                                  r.external = true
                WITH r
                MATCH (p:Policy {arn: $arn})
                MERGE (p)-[:MayAssume]->(r)
            """, role_arn=role_arn, arn=policy_arn)
            tx.run("""
                MERGE (a:Account {id: $account_id})
                    ON CREATE SET a.arn = 'arn:aws:iam::' + $account_id + ':root', a.external = true
                WITH a
                MATCH (r:Role {arn: $role_arn})
                MERGE (a)-[:ContainsIdentity]->(r)
            """, account_id=role_arn.split(":")[4], role_arn=role_arn)

    # Link to roles (CanPassRole):
    for role_arn in results["pass_roles"]:
        if role_arn == "*":
            tx.run("""
                MATCH (p:Policy {arn: $arn}), (g:Global {name: "*"})
                MERGE (p)-[:CanPassRole]->(g)
            """, arn=policy_arn)
        else:
            tx.run("""
                MERGE (r:Role {arn: $role_arn})
                    ON CREATE SET r.name = split($role_arn, '/')[1],
                                  r.accountId = split($role_arn, ':')[4],
                                  r.maxSessionDuration = 3600,
                                  r.external = true
                WITH r
                MATCH (p:Policy {arn: $arn})
                MERGE (p)-[:CanPassRole]->(r)
            """, role_arn=role_arn, arn=policy_arn)
            tx.run("""
                MERGE (a:Account {id: $account_id})
                    ON CREATE SET a.arn = 'arn:aws:iam::' + $account_id + ':root', a.external = true
                WITH a
                MATCH (r:Role {arn: $role_arn})
                MERGE (a)-[:ContainsIdentity]->(r)
            """, account_id=role_arn.split(":")[4], role_arn=role_arn)

# Wrapper for the analysis and updates to Neo4j:
def analyze_policy_cache(policy_cache, driver):
    count = 0
    for policy_arn, meta in policy_cache.items():
        count += 1
        print(f"Policy ({count}/{len(policy_cache)}): {policy_arn}".ljust(100), end="\r")
        document = meta.get("Document")
        version_id = meta.get("VersionId")

        statements = document.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        results = {
            "flags": set(),
            "services": set(),
            "may_assume_roles": set(),
            "pass_roles": set(),
            "conditional": False
        }

        for stmt in statements:
            analyze_conditions(stmt, results)
            analyze_wildcards(stmt, results)
            analyze_admin_access(stmt, results)
            analyze_blacklists(stmt, results)
            analyze_service_wildcards(stmt, results)
            analyze_sts_assume(stmt, results)
            analyze_pass_role(stmt, results)

        # Write to Neo4j:
        with driver.session() as session:
            session.execute_write(apply_policy_analysis_to_neo4j, policy_arn, results, version_id)

# Update risks for identities:
def assign_identity_risk_scores(tx):
    tx.run("""
        MATCH (i:User)-[:HasPolicy|MemberOf*1..2]->(p:Policy)
        WITH i, max(p.riskScore) AS maxScore
        SET i.riskScore = coalesce(maxScore, 0)
    """)
    tx.run("""
        MATCH (i:Group)-[:HasPolicy]->(p:Policy)
        WITH i, max(p.riskScore) AS maxScore
        SET i.riskScore = coalesce(maxScore, 0)
    """)
    tx.run("""
        MATCH (i:Role)-[:HasPolicy]->(p:Policy)
        WITH i, max(p.riskScore) AS maxScore
        SET i.riskScore = coalesce(maxScore, 0)
    """)

################################
#                              #
#    Configuration Handling    #
#                              #
################################

# Create default configuration file:
def write_config_file(config=None):
    if not config:
        config = {
            "Credentials": {
                "Uri": "bolt://localhost:7687",
                "Username": "neo4j",
                "Password": "neo4j"
            },
            "Queries": [
                {
                    "Description": "[GRAPH] Find paths to the 'AdministratorAccess' policy.",
                    "Query": "MATCH s=(a)-[r*1..4]->(p:Policy) WHERE NOT (a)-[:ContainsIdentity]->() AND p.name = 'AdministratorAccess' RETURN s"
                },
                {
                    "Description": "[GRAPH] Find paths to policies with admin access.",
                    "Query": "MATCH s=(a)-[r*1..4]->(p:Policy) WHERE NOT (a)-[:ContainsIdentity]->() AND p.hasAdminAccess RETURN s"
                },
                {
                    "Description": "[GRAPH] Find global permissions and resources.",
                    "Query": "MATCH p=()-[r*1..2]-(g:Global) RETURN p"
                },
                {
                    "Description": "[GRAPH] Find all policies attached to users.",
                    "Query": "MATCH s=(u:User)-[:HasPolicy|MemberOf*1..2]->(p:Policy) RETURN s"
                },
                {
                    "Description": "[TABLE] Find all policies attached to users.",
                    "Query": "MATCH (u:User)-[:HasPolicy|MemberOf*1..2]->(p:Policy) RETURN u.name AS UserName, p.name AS PolicyName, p.riskScore AS RiskScore ORDER BY RiskScore DESC"
                },
                {
                    "Description": "[GRAPH] Find all risky users.",
                    "Query": "MATCH (o:User) WHERE o.riskScore > 50 RETURN o"
                },
                {
                    "Description": "[GRAPH] Find all risky groups.",
                    "Query": "MATCH (o:Group) WHERE o.riskScore > 50 RETURN o"
                },
                {
                    "Description": "[GRAPH] Find all risky roles.",
                    "Query": "MATCH (o:Role) WHERE o.riskScore > 50 RETURN o"
                },
                {
                    "Description": "[GRAPH] Find paths from owned identities to administrative access.",
                    "Query": "MATCH s=(o)-[r*1..4]->(p:Policy) WHERE o.owned AND p.hasAdminAccess RETURN s"
                },
                {
                    "Description": "[GRAPH] Find owned identities.",
                    "Query": "MATCH (o) WHERE o.owned AND NOT (o:Global) RETURN o"
                },
                {
                    "Description": "[TABLE] Find old access keys for users.",
                    "Query": "MATCH s=(u:User)-[:HasAccessKey]->(a:AccessKey) RETURN u.name AS UserName, a.accessKeyId AS AccessKey, a.status as Status, a.ageDays as Age ORDER BY Status, Age DESC"
                },
                {
                    "Description": "[TABLE] Find risky users with access keys.",
                    "Query": "MATCH (u:User) WHERE u.accessKeyCount > 0 AND u.riskScore > 50 RETURN u.name AS Name, u.riskScore AS Risk ORDER BY Risk DESC"
                },
                {
                    "Description": "[GRAPH] Find identities with full control over IAM.",
                    "Query": "MATCH p=(a)-[:HasPolicy|HasFullControl*1..2]->(s:Service) WHERE s.name = 'iam.amazonaws.com' RETURN p"
                },
                {
                    "Description": "[GRAPH] Find identities with full control over EC2.",
                    "Query": "MATCH p=(a)-[:HasPolicy|HasFullControl*1..2]->(s:Service) WHERE s.name = 'ec2.amazonaws.com' RETURN p"
                },
                {
                    "Description": "[TABLE] Get top 10 services with most 'full control' policies.",
                    "Query": "MATCH (:Policy)-[:HasFullControl]->(s:Service) RETURN s.name AS Service, COUNT(*) AS ControlCount ORDER BY ControlCount DESC LIMIT 10"
                },
                {
                    "Description": "[TABLE] Get top 30 identity ARNs with highest risk.",
                    "Query": "MATCH (p:User|Group|Role) WHERE p.riskScore IS NOT NULL RETURN p.arn AS ARN, p.riskScore AS RiskScore ORDER BY p.riskScore DESC LIMIT 30"
                },
                {
                    "Description": "[TABLE] Find policies that allow to assume external or generic roles.",
                    "Query": "MATCH (p:Policy)-[:MayAssume]->(r:Role) WHERE r.external RETURN p.name AS PolicyName, p.arn AS PolicyArn, r.arn AS RoleArn ORDER BY p.name"
                },
                {
                    "Description": "[TABLE] Find IAM identities with policies that have wildcard actions.",
                    "Query": "MATCH (i:User|Group|Role)-[:HasPolicy]->(p:Policy) WHERE p.hasWildcardAction RETURN i.arn AS ARN, p.name as PolicyName, p.riskScore AS Risk ORDER BY Risk DESC"
                },
                {
                    "Description": "[TABLE] Find IAM identities with policies that have wildcard resources.",
                    "Query": "MATCH (i:User|Group|Role)-[:HasPolicy]->(p:Policy) WHERE p.hasWildcardResource RETURN i.arn AS ARN, p.name as PolicyName, p.riskScore AS Risk ORDER BY Risk DESC"
                },
                {
                    "Description": "[TABLE] Find IAM identities with policies that have action blacklists.",
                    "Query": "MATCH (i:User|Group|Role)-[:HasPolicy]->(p:Policy) WHERE p.blacklistAction RETURN i.arn AS ARN, p.name as PolicyName, p.riskScore AS Risk ORDER BY Risk DESC"
                },
                {
                    "Description": "[TABLE] Find IAM identities with policies that have resource blacklists.",
                    "Query": "MATCH (i:User|Group|Role)-[:HasPolicy]->(p:Policy) WHERE p.blacklistResource RETURN i.arn AS ARN, p.name as PolicyName, p.riskScore AS Risk ORDER BY Risk DESC"
                },
                {
                    "Description": "[GRAPH] Find risky roles assumable by accounts.",
                    "Query": "MATCH s=(a:Account)-[:CanAssume]->(r:Role)-[:HasPolicy]->(p:Policy) WHERE p.riskScore > 40 RETURN s"
                },
                {
                    "Description": "[TABLE] Find EC2 instances by potential risk.",
                    "Query": "MATCH (i:EC2Instance)-[:UsesProfile]->(p:InstanceProfile)-[:HasRole]->(r:Role) RETURN i.instanceId AS InstanceId, p.name AS ProfileName, r.name AS RoleName, r.riskScore AS Risk ORDER BY Risk DESC"
                },
                {
                    "Description": "[TABLE] Find roles assumable by services.",
                    "Query": "MATCH (s:Service)-[:CanAssume]->(r:Role) RETURN s.name AS Service, r.name AS Role ORDER BY Service"
                },
                {
                    "Description": "[GRAPH] Find identities that may pass roles.",
                    "Query": "MATCH p=(o)-[:HasPolicy|CanPassRole*1..2]->(r:Role) RETURN p"
                },
                {
                    "Description": "[TABLE] Get quantities of different identities.",
                    "Query": "MATCH (n) WHERE n:User OR n:Group OR n:Role OR n:Policy RETURN labels(n)[0] AS Type, count(n) AS Count ORDER BY Count DESC"
                },
                {
                    "Description": "[TABLE] Get quantities of all node types.",
                    "Query": "MATCH (n) RETURN labels(n)[0] AS Type, count(n) AS Count ORDER BY Count DESC"
                },
                {
                    "Description": "[GRAPH] Find assume role loops.",
                    "Query": "MATCH s=(a:Role)-[:HasPolicy|CanAssume|MayAssume*1..4]->(b:Role) WHERE a.arn = b.arn RETURN s"
                },
                {
                    "Description": "[GRAPH] Validate may assume relationships.",
                    "Query": "MATCH s=(a:Account)-[:ContainsIdentity]->(i)-[:HasPolicy]-(p:Policy)-[:MayAssume]->(r:Role) RETURN s"
                },
                {
                    "Description": "[GRAPH] Get path between two ARNs (replace arn_src and arn_dst).",
                    "Query": "MATCH s=(a {arn: 'arn_src'})-[r*1..5]->(b {arn: 'arn_dst'}) RETURN s"
                }
            ]
        }
        update_config_credentials(config)
    with open('config.json', 'w') as config_file:
        config_file.write(json.dumps(config))

# Load current configuration file:
def load_configuration_file():
    if not os.path.exists('config.json'):
        write_config_file()

    with open('config.json', 'r') as config_file:
        config_data = config_file.read()
        config = json.loads(config_data)
        return config

# Update credentials:
def update_config_credentials(config):
    # Get credentials from user:
    print("Please provide the Neo4j credentials (press enter to keep value).")
    uri = input(f"Enter URI ('{config['Credentials']['Uri']}'): ")
    username = input(f"Enter Username ('{config['Credentials']['Username']}'): ")
    password = input(f"Enter Password ('{'*' * len(config['Credentials']['Password'])}'): ")
    # Update config based on changes:
    if uri:
        config['Credentials']['Uri'] = uri
    if username:
        config['Credentials']['Username'] = username
    if password:
        config['Credentials']['Password'] = password
    # Write changes:
    write_config_file(config)

# Show the Neo4j credentials:
def show_neo4j_credentials(config, cleartext):
    uri = config['Credentials']['Uri']
    username = config['Credentials']['Username']
    password = config['Credentials']['Password']
    print("Neo4j Credentials:\n==================")
    print(f"Neo4j URI: {uri}\nUsername:  {username}\nPassword:  {password if cleartext else '*' * len(password)}\n")

###########################
#                         #
#    Interactive Shell    #
#                         #
###########################

# Modify environment variables:
def set_environment_variable(var_name, var_value):
    os.environ[var_name] = var_value

# Handle help data for single command:
def show_help_data(name, command_data):
    print(f'{name}\n{"=" * len(name)}\nSyntax: {command_data["Syntax"]}\n{command_data["Description"]}\n')

# Handle shell help menu:
def show_shell_help(command=None):
    if command:
        command = ' '.join(command)
        if command in command_help:
            command_data = command_help[command]
            show_help_data(command, command_data)
        else:
            print(f"Error: Command '{command}' is not valid.")
    else:
        for command_name in command_help:
            show_help_data(command_name, command_help[command_name])

# Handle shell commands:
def execute_command(command, config):
    # Split command by spaces:
    tokens = command.strip().split()

    # Handle the commands:
    match tokens:
        # Handle 'help' command and variants:
        case ['help']:
            show_shell_help()
        case ['help', *cmd]:
            show_shell_help(cmd)
        # Handle 'list' command:
        case ['list']:
            print("Command List:\n=============")
            for cmd in command_help:
                print(f'  - {command_help[cmd]["Syntax"]}')
            print()
        # Handle 'clear_database' command:
        case ['clear_database']:
            with driver.session() as session:
                print("Clearing Neo4j database.")
                session.execute_write(clear_graph)
        # Handle 'start_scan' command and variants:
        case ['start_scan']:
            start_aws_analysis()
        case ['start_scan', 'clear']:
            start_aws_analysis(True)
        # Handle 'query' command and variants:
        case ['query', 'list']:
            print("Queries List:\n=============")
            for idx in range(len(config['Queries'])):
                print(f"{(idx+1):3}. {config['Queries'][idx]['Description']}")
            print()
        case ['query', 'add']:
            description = input("Enter Description: ")
            query = input("Enter Query: ")
            config['Queries'].append({"Description": description, "Query": query})
            write_config_file(config)
        case ['query', 'set', idx]:
            try:
                print("Press enter to not modify field.")
                description = input("Enter Description: ")
                query = input("Enter Query: ")
                if description:
                    config['Queries'][int(idx)-1]['Description'] = description
                if query:
                    config['Queries'][int(idx)-1]['Query'] = query
                write_config_file(config)
            except:
                print(f"Error: Index '{idx}' is not valid.\n")
        case ['query', 'get', idx]:
            try:
                description, query = config['Queries'][int(idx)-1].values()
                print(f'Requested query: {description}\n\n{query}\n')
            except:
                print(f"Error: Index '{idx}' is not valid.\n")
        case ['query', 'delete', idx]:
            try:
                del config['Queries'][int(idx)-1]
                write_config_file(config)
            except:
                print(f"Error: Index '{idx}' is not valid.\n")
        # Handle 'set' command and variants:
        case ['set', 'env', var_name, *var_value]:
            set_environment_variable(var_name, ' '.join(var_value))
        case ['set', 'profile', name]:
            set_environment_variable('AWS_PROFILE', name)
        case ['set', 'credentials']:
            update_config_credentials(config)
        case ['set', 'owned', arn, value]:
            if value == 'true':
                with driver.session() as session:
                    session.execute_write(set_ownership_for_identity, arn, True)
            elif value == 'false':
                with driver.session() as session:
                    session.execute_write(set_ownership_for_identity, arn, False)
            else:
                print(f"Error: Ownership value must be either true or false.\n")
        # Handle 'get' command and variants:
        case ['get', 'profile']:
            print(f'Current AWS Profile: {os.environ.get("AWS_PROFILE", "default")}\n')
        case ['get', 'credentials']:
            show_neo4j_credentials(config, False)
        case ['get', 'credentials', 'cleartext']:
            show_neo4j_credentials(config, True)
        # Default behavior:
        case _:
            print(f"Error: Command '{command}' is not valid.\n")

# Initiate and handle the interactive shell:
def start_interactive_shell(config):
    print("Initiating interactive shell...")
    print("Type 'help' for more information.\n")
    while True:
        command = input("aws> ")
        if command in ('exit', 'quit'):
            break
        execute_command(command, config)
    print("Bye!\n")

########################
#                      #
#    Code Functions    #
#                      #
########################

# Helper function to map identities:
def infer_label_from_arn(arn):
    if ":user/" in arn:
        return "User"
    elif ":group/" in arn:
        return "Group"
    elif ":role/" in arn:
        return "Role"
    return "Unknown"

# Just to feel fancier:
def show_banner():
    banner = r"""
      __          _______    _____      _ _               _    _             _            
     /\ \        / / ____|  |  __ \    | (_)             | |  | |           | |           
    /  \ \  /\  / / (___    | |__) |__ | |_  ___ _   _   | |__| |_   _ _ __ | |_ ___ _ __ 
   / /\ \ \/  \/ / \___ \   |  ___/ _ \| | |/ __| | | |  |  __  | | | | '_ \| __/ _ \ '__|
  / ____ \  /\  /  ____) |  | |  | (_) | | | (__| |_| |  | |  | | |_| | | | | ||  __/ |   
 /_/    \_\/  \/  |_____/   |_|   \___/|_|_|\___|\__, |  |_|  |_|\__,_|_| |_|\__\___|_|   
                                                  __/ |                                   
Created by: Idabian                              |___/                                    
Version: 1.0.0                                                                           
"""
    print(banner)

# Handle the environment scan:
def start_aws_analysis(clear=False):
    # Handle dynamic profile changes:
    global iam, sts, ec2
    session = boto3.Session()
    iam = session.client('iam')
    sts = session.client('sts')
    ec2 = session.client('ec2', region_name='us-east-1')

    # Execution starts here:
    print("Fetching AWS Information...")
    print("Fetching IAM account.")
    account_id = sts.get_caller_identity()['Account']
    account_arn = f"arn:aws:iam::{account_id}:root"

    users, groups = list_users_and_groups()
    roles = list_roles()

    with driver.session() as session:
        if clear:
            print("Clearing Neo4j database.")
            session.execute_write(clear_graph)
        session.execute_write(create_account, account_id, account_arn)
        session.execute_write(create_global_node)

        # (offline) Adding roles to Neo4j:
        print(f"Adding {len(roles)} roles.".ljust(100))
        for count, role in enumerate(roles, 1):
            role_arn = role['Arn']
            print(f"Role ({count}/{len(roles)}): {role['RoleName']}".ljust(100), end="\r")
            session.execute_write(create_role, role, account_id)

        # (offline) Adding groups to Neo4j:
        print(f"Adding {len(groups)} groups.".ljust(100))
        for count, group in enumerate(groups, 1):
            group_arn = group['Arn']
            print(f"Group ({count}/{len(groups)}): {group['GroupName']}".ljust(100), end="\r")
            session.execute_write(create_group, group, account_id)
            session.execute_write(create_identity_membership, account_id, "Group", group_arn)

        # (online) Adding users and access keys to Neo4j:
        print(f"Adding {len(users)} users.".ljust(100))
        process_users_parallel(users, account_id)

        # (online) Adding user relationships to Neo4j:
        print("Adding group memberships and policies for users...".ljust(100))
        process_user_links_parallel(users, account_id)

        # (online) Adding policies and relationships for groups to Neo4j:
        print("Adding policies for groups...".ljust(100))
        process_group_policies_parallel(groups, account_id)
        
        # (offline) Adding role trusts to Neo4j:
        print(f"Adding trusts for roles...".ljust(100))
        for count, role in enumerate(roles, 1):
            role_arn = role['Arn']
            print(f"Role ({count}/{len(roles)}): {role['RoleName']}".ljust(100), end="\r")

            # Adding NotPrinciapl support and role external ids to Neo4j:
            policy = role['AssumeRolePolicyDocument']
            external_ids = []
            for stmt in policy.get('Statement', []):
                # Handle NotPrinciapl global access:
                if stmt.get('Effect') == 'Allow' and 'NotPrincipal' in stmt:
                    session.execute_write(create_may_assume_global, role_arn)

                # Handle external id for relevant roles:
                condition = stmt.get('Condition', {})
                if 'StringEquals' in condition:
                    ext_id = condition['StringEquals'].get('sts:ExternalId')
                    if ext_id:
                        if isinstance(ext_id, list):
                            external_ids.extend(ext_id)
                        else:
                            external_ids.append(ext_id)
            if external_ids:
                session.execute_write(set_external_id_on_role, role['Arn'], external_ids)

            # Actually adding the trusts:
            trust_principals = get_trust_principals_from_assume_role_policy(policy)
            for trust_type, value in trust_principals:
                if trust_type == 'Service':
                    session.execute_write(create_service_node, value)
                    session.execute_write(create_can_assume, 'Service', 'name', value, role['Arn'])
                elif trust_type == 'Federated':
                    session.execute_write(create_federated_node, value)
                    session.execute_write(create_can_assume, 'FederatedIdentity', 'arn', value, role['Arn'])
                elif trust_type == 'IAM':
                    session.execute_write(create_stub_iam_identity, value)
                    session.execute_write(create_can_assume, infer_label_from_arn(value), 'arn', value, role['Arn'])
                elif trust_type == 'Account':
                    session.execute_write(create_account_trust, value, role['Arn'])
                elif trust_type == "Global":
                    session.execute_write(create_can_assume, 'Global', 'name', '*', role['Arn'])
                elif trust_type == "GlobalWildcard":
                    session.execute_write(create_stub_iam_identity, value)
                    session.execute_write(create_can_assume, infer_label_from_arn(value), 'arn', value, role['Arn'])

        # (online) Adding policies and relationships for roles to Neo4j:
        print(f"Adding policies for roles...".ljust(100))
        process_role_policies_parallel(roles, account_id)
    
        # (offline) Handling instance profiles:
        print("Fetching Instance Profiles.".ljust(100))
        instance_profiles = paginate_list('list_instance_profiles', 'InstanceProfiles')
        print(f"Adding {len(instance_profiles)} instance profiles.".ljust(100))
        for count, profile in enumerate(instance_profiles, 1):
            print(f"InstanceProfile ({count}/{len(instance_profiles)}): {profile['InstanceProfileName']}".ljust(100), end="\r")
            session.execute_write(create_instance_profile, profile)

            # Linking roles to profiles:
            for role in profile['Roles']:
                session.execute_write(create_profile_role_relationship, profile['Arn'], role['Arn'])
        
        # (online) Handle EC2 Instances:
        print("Fetching EC2 regions and instances.".ljust(100))
        regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
        process_ec2_parallel(regions)

        # Handle policy cache and analyze policies:
        print("Collecting policy documents for deep inspection...".ljust(100))
        policy_cache = build_policy_cache_parallel(users, groups, roles)
        print(f"Analyzing {len(policy_cache)} policies.".ljust(100))
        analyze_policy_cache(policy_cache, driver)
        print("Adding score to identities.".ljust(100))
        session.execute_write(assign_identity_risk_scores)

    print("Finished populating the Neo4j database. You can visit the web console and get the information.\n")

# Main function:
def main():
    # Show fancy banner:
    show_banner()

    # Handle command-line arguments:
    parser = argparse.ArgumentParser()
    parser.add_argument('--clear', action='store_true', help='clear the database before scanning')
    parser.add_argument('--interactive', action='store_true', help='starts interactive shell instead of analysing')
    parser.add_argument('--credentials', action='store_true', help='update the credentials of the config file (password is cleartext)')
    args = parser.parse_args()
    
    # Load configuration file:
    config = load_configuration_file()

    if args.credentials:
        # Update the credentials to the Neo4j database:
        update_config_credentials(config)
    elif args.interactive:
        # Handle interactive shell:
        connect_to_neo4j(config)
        start_interactive_shell(config)
    else:
        # Start the scan:
        connect_to_neo4j(config)
        start_aws_analysis(args.clear)

if __name__ == "__main__":
    main()
