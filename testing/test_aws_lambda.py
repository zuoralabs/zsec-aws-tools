import boto3
import zsec_aws_tools.aws_lambda as zaws_lambda
import io
import zipfile
import textwrap


def create_test_lambda_code():
    code = textwrap.dedent("""
    
    def lambda_handler(event, context):
        print(event)
    
        return 1
    """)

    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zinfo_or_arcname='main.py', data=code)

    return output.getvalue()


def test_aws_lambda():
    session = boto3.Session(profile_name='test')

    code: bytes = create_test_lambda_code()

    fn = zaws_lambda.FunctionResource(
        session=session, region_name='us-east-1',
        name='test_lambda_1', ensure_exists=True,
        config=dict(
            Code={'ZipFile': code},
            Runtime='python3.7',
            Role='arn:aws:iam::438453513788:role/service-role/x-lambda-role-1',
            Handler='main.lambda_handler',
            Timeout=3,
        ))

    fn.put(force=True)
    
