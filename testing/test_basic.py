from zsec_aws_tools.basic import scroll
import boto3

session = boto3.Session(profile_name='test')


def test_scroll():
    iam = session.client('iam')
    policies = list(scroll(iam.list_policies))
    assert 10 < len(policies)

    assert list(filter(lambda x: x['PolicyName'] == 'ReadOnlyAccess', policies))
