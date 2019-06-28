import pytest
import boto3
import zsec_aws_tools.iam as zaws_iam
from toolz import assoc
from zsec_aws_tools.aws_lambda import default_assume_role_policy_document_for_lambda
from zsec_aws_tools.basic import manager_tag_key
from typing import Generator
import json
import uuid

session = boto3.Session(profile_name='test', region_name='us-east-1')


@pytest.fixture
def aws_managed_iam_policy() -> Generator[zaws_iam.Policy, None, None]:
    policy = zaws_iam.Policy(name='ReadOnlyAccess', session=session)
    yield policy


@pytest.fixture
def local_iam_policy() -> Generator[zaws_iam.Policy, None, None]:
    policy = zaws_iam.Policy(name='TestPolicy-abtasxabatsawk',
                             session=session,
                             ztid=uuid.UUID('41294B17-2288-4871-AC10-1C3209E99095'),
                             config=dict(PolicyDocument={
                                 "Version": "2012-10-17",
                                 "Statement": [
                                     {
                                         "Sid": "AllowLambda",
                                         "Action": "lambda:*",
                                         "Effect": "Allow",
                                         "Resource": "*"
                                     }
                                 ]
                             }))
    yield policy
    policy.delete(not_exists_ok=True)


def test_aws_managed_iam_policy(aws_managed_iam_policy):
    assert aws_managed_iam_policy.exists
    assert aws_managed_iam_policy.describe()['Arn'] == "arn:aws:iam::aws:policy/ReadOnlyAccess"


def test_locally_managed_iam_policy(local_iam_policy):
    local_iam_policy.put(force=True)
    assert local_iam_policy.exists
    assert local_iam_policy.describe()['Arn'] == local_iam_policy.arn


def test_boto3_iam_service_resource():
    """Not a test of my code, just a sanity check of boto3"""
    iamr = session.resource('iam', region_name='us-east-1')
    policy_resource = iamr.Policy("arn:aws:iam::aws:policy/ReadOnlyAccess")
    assert policy_resource.arn == "arn:aws:iam::aws:policy/ReadOnlyAccess"


def test_iam_role(aws_managed_iam_policy):
    'test_iam_role_1_role'
    role = zaws_iam.Role(
        name='test_lambda_1_role', session=session,
        ztid=uuid.UUID('42d02a7d-a8bf-c662-22fb-9ee83246bd8b'),
        config=dict(Path='/test/',
                    AssumeRolePolicyDocument=default_assume_role_policy_document_for_lambda,
                    Policies=[aws_managed_iam_policy]))
    role.put(wait=True)

    # change the manager tag
    tags = {manager_tag_key: 'alt_manager'}
    role.config = assoc(role.config, 'Tags', tags)
    assert {tag['Key']: tag['Value'] for tag in role.processed_config['Tags']}[manager_tag_key] == 'alt_manager'
    with pytest.raises(Exception):
        role.put(wait=True, force=False)

    assert role.arn.startswith("arn")
    assert role.arn.endswith(role.name)

    assert aws_managed_iam_policy.arn.startswith("arn")
    assert aws_managed_iam_policy.arn.endswith(aws_managed_iam_policy.name)

    assert aws_managed_iam_policy in role.list_role_policies()
    assert zaws_iam.Policy(name='AWSDenyAll', session=session) not in role.list_role_policies()

    iamr = session.resource('iam', region_name='us-east-1')
    policy = iamr.RolePolicy(role_name=role.name, name='ReadOnlyAccess')

    # print(policy.policy_name)
    # print(policy.policy_document)

    role.detach_all_policies()
    role.delete()
    role.wait_until_not_exists()
