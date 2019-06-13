import boto3
import zsec_aws_tools.aws_lambda as zaws_lambda
import zsec_aws_tools.iam as zaws_iam
import io
import zipfile
import textwrap
import json
import logging
import time
from botocore.exceptions import ClientError

logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.basicConfig(level=logging.WARNING)
zaws_lambda.logger.setLevel(logging.INFO)


def create_test_lambda_code():
    code = textwrap.dedent("""
    
    def lambda_handler(event, context):
        print(event)
    
        return "147306"
    """)

    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zinfo_or_arcname='main.py', data=code)
        # set permissions
        zf.filelist[0].external_attr = 0o0666 << 16

    return output.getvalue()


def test_aws_lambda():
    session = boto3.Session(profile_name='test', region_name='us-east-1')

    code: bytes = create_test_lambda_code()

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
        name='test_lambda_1_role', session=session,
        config=dict(Path='/test/',
                    AssumeRolePolicyDocument=json.dumps(assume_role_policy_document, ),
                    Policies=[policy]))
    role.put(wait=True)

    # print(list(role.boto3_resource().policies.all()))
    # print(list(role.boto3_resource().attached_policies.all()))

    try:
        # attached_policies = list(role.list_role_policies())
        fn = zaws_lambda.FunctionResource(
            name='test_lambda_1',
            session=session,
            config=dict(
                Code={'ZipFile': code},
                Runtime='python3.7',
                Role=role,
                Handler='main.lambda_handler',
                Timeout=3,
            ))
        fn.put(force=True, wait=True)
        resp = fn.invoke(json_codec=True, Payload={'a': 'a'})
        assert resp == "147306"
        fn.delete()
        fn.await_deletion()
    finally:
        role.detach_all_policies()
        role.delete()
        role.await_deletion()
