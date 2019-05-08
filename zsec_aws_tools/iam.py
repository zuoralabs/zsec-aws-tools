import logging
import boto3


logger = logging.getLogger(__name__)

CREDENTIALS_TEMPLATE = """
[{profile}]
aws_access_key_id = {aws_access_key_id}
aws_secret_access_key = {aws_secret_access_key}
aws_session_token = {aws_session_token}
"""


def assume_role_response_to_session_kwargs(assume_role_resp):
    """Convert assume role response to kwargs for boto3.Session

    Also useful for creating AWS credentials file.

    """
    return dict(aws_access_key_id = assume_role_resp['Credentials']['AccessKeyId'],
                aws_secret_access_key = assume_role_resp['Credentials']['SecretAccessKey'],
                aws_session_token = assume_role_resp['Credentials']['SessionToken'],)


def assume_role_session(session: boto3.Session,
                        RoleArn: str,
                        RoleSessionName: str = 'automation',
                        **kwargs) -> boto3.Session:
    """Get session using assume-role.

    Passes kwargs to sts.assume_role

    To catch AccessDenied::

        try:
            assume_role_session(...)
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "AccessDenied":
                broken_access[account_number] = accounts[account_number]

    """
    resp = session.client('sts').assume_role(
        RoleArn=RoleArn,
        RoleSessionName=RoleSessionName,
        **kwargs)

    return boto3.Session(
        aws_access_key_id = resp['Credentials']['AccessKeyId'],
        aws_secret_access_key = resp['Credentials']['SecretAccessKey'],
        aws_session_token = resp['Credentials']['SessionToken'],
    )
