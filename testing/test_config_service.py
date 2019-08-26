import string
import random
import boto3
import pytest
import logging
import textwrap
import uuid

import zsec_aws_tools.aws_lambda as zaws_lambda
import zsec_aws_tools.config_service as zaws_config_service

from test_aws_lambda import create_test_lambda_code, role_for_lambda, session


@pytest.fixture
def fn(session, role_for_lambda):
    test_code = textwrap.dedent("""
        
        def lambda_handler(event, context):
            print(event)
        """)

    code: bytes = create_test_lambda_code(test_code)

    fn = zaws_lambda.FunctionResource(
        name='test_lambda_1',
        ztid=uuid.UUID('533a2b7c-fec5-4702-b6d0-81a9bb1f8f0f'),
        session=session,
        config=dict(
            Code={'ZipFile': code},
            Runtime='python3.7',
            Role=role_for_lambda,
            Handler='main.lambda_handler',
            Timeout=3,
            Permissions=[{
                "StatementId": "ConfigRuleLambdaPermissionStatement",
                "Principal": "config.amazonaws.com",
                "Action": "lambda:InvokeFunction",
            }]
        ))

    fn.put(force=True, wait=True)

    yield fn

    fn.delete()
    fn.wait_until_not_exists()


@pytest.fixture
def my_config_rule(session: boto3.Session, fn: zaws_lambda.FunctionResource):
    random_str = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))

    resp = fn.invoke(json_codec=True, Payload={'a': 'a'})

    config_rule_x = zaws_config_service.ConfigRule(
        name="test-config-rule-" + random_str,
        session=session,
        config=dict(ConfigRule=dict(Scope=dict(ComplianceResourceTypes=['AWS::EC2::VOLUME']),
                                    Source=dict(Owner='CUSTOM_LAMBDA',
                                                SourceIdentifier=fn.arn,
                                                SourceDetails=[
                                                    dict(EventSource='aws.config',
                                                         MessageType='ConfigurationItemChangeNotification'),
                                                    dict(EventSource='aws.config',
                                                         MessageType='ScheduledNotification',
                                                         MaximumExecutionFrequency='TwentyFour_Hours')
                                                ])

                                    )))

    yield config_rule_x

    # don't care about consistency with bucket_x.exists; this is a fixture not a test
    config_rule_x.delete(not_exists_ok=True)


def test_config_rule_creation_and_deletion(my_config_rule: zaws_config_service.ConfigRule, caplog):
    caplog.set_level(logging.CRITICAL)

    assert not my_config_rule.exists
    my_config_rule.put(wait=True)
    assert my_config_rule.exists

    my_config_rule.delete()
    my_config_rule.wait_until_not_exists()
    assert not my_config_rule.exists


def test_config_rule_arn(my_config_rule, caplog):
    caplog.set_level(logging.CRITICAL)
    my_config_rule.put()

    arn = my_config_rule.arn
    assert arn
    assert arn.split('/')[-1].startswith('config-rule')
    assert arn.startswith('arn:aws')

