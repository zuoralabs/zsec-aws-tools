import boto3
import zsec_aws_tools.iam as zaws_iam
import json
import uuid

session = boto3.Session(profile_name='test', region_name='us-east-1')


def test_iam_policy():
    policy = zaws_iam.Policy(name='ReadOnlyAccess', session=session)
    assert policy.exists
    #policy.ensure_exists()
    #policy.wait()

    policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    assert policy.describe()['Arn'] == policy_arn


def test_boto3_iam_service_resource():
    """Not a test of my code, just a sanity check"""
    iamr = session.resource('iam', region_name='us-east-1')
    policy_bresource = iamr.Policy("arn:aws:iam::aws:policy/ReadOnlyAccess")
    assert policy_bresource.arn == "arn:aws:iam::aws:policy/ReadOnlyAccess"


def test_iam_role():
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    iamr = session.resource('iam', region_name='us-east-1')
    policy = zaws_iam.Policy(name='ReadOnlyAccess', session=session)

    'test_iam_role_1_role'
    role = zaws_iam.Role(
        name='test_lambda_1_role', session=session,
        ztid=uuid.UUID('42d02a7d-a8bf-c662-22fb-9ee83246bd8b'),
        config=dict(Path='/test/',
                    AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
                    Policies=[policy]))
    role.put(wait=True)

    role_arn = role.describe()[role.arn_key]
    assert role_arn == role.boto3_resource().arn

    assert policy in role.list_role_policies()
    assert zaws_iam.Policy(name='AWSDenyAll', session=session) not in role.list_role_policies()

    policy = iamr.RolePolicy(role_name=role.name, name='ReadOnlyAccess')

    #print(policy.policy_name)
    #print(policy.policy_document)

    role.detach_all_policies()
    role.delete()
    role.await_deletion()
