import boto3
import zsec_aws_tools.aws_lambda as zaws_lambda
import zsec_aws_tools.iam as zaws_iam
import io
import zipfile
import textwrap
import json
import logging
import uuid
import pytest


logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.basicConfig(level=logging.WARNING)
zaws_lambda.logger.setLevel(logging.INFO)


def create_test_lambda_code(code):

    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zinfo_or_arcname='main.py', data=code)
        # set permissions
        zf.filelist[0].external_attr = 0o0666 << 16

    return output.getvalue()


@pytest.fixture
def session():
    yield boto3.Session(profile_name='test', region_name='us-east-1')


@pytest.fixture
def role_for_lambda(session):
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

    policy = zaws_iam.Policy(index_id="arn:aws:iam::aws:policy/ReadOnlyAccess", session=session)
    role = zaws_iam.Role(
        name='test_lambda_1_role',
        ztid=uuid.UUID('1b761bcf-eaef-b927-ca02-cc6c927b228d'),
        session=session,
        config=dict(Path='/test/',
                    AssumeRolePolicyDocument=json.dumps(assume_role_policy_document, ),
                    Policies=[policy]))
    role.put(wait=True)

    yield role

    role.detach_all_policies()
    role.delete()
    role.wait_until_not_exists()


@pytest.fixture
def fn(session, role_for_lambda):
    test_code = textwrap.dedent("""
        
        def lambda_handler(event, context):
            print(event)
        
            return "147306"
        """)

    code: bytes = create_test_lambda_code(test_code)

    fn = zaws_lambda.FunctionResource(
        name='test_lambda_1',
        ztid=uuid.UUID('6db733ed-c2f0-ac73-78ec-8ab2bdffd124'),
        session=session,
        config=dict(
            Code={'ZipFile': code},
            Runtime='python3.7',
            Role=role_for_lambda,
            Handler='main.lambda_handler',
            Timeout=3,
        ))

    yield fn

    fn.delete()
    fn.wait_until_not_exists()


def test_aws_lambda(session, role_for_lambda, fn):
    # print(list(role.boto3_resource().policies.all()))
    # print(list(role.boto3_resource().attached_policies.all()))
    # attached_policies = list(role.list_role_policies())

    fn.put(force=True, wait=True)

    arn = fn.arn
    assert arn.endswith(fn.name)
    assert arn.startswith("arn:aws:lambda:")

    resp = fn.invoke(json_codec=True, Payload={'a': 'a'})
    assert resp == "147306"
