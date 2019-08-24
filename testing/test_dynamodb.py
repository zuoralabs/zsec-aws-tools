import string
import random
import boto3
import pytest
import zsec_aws_tools.dynamodb as zaws_dynamodb
import logging


@pytest.fixture
def my_table():
    session = boto3.Session(profile_name='test', region_name='us-east-1')

    random_str = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))

    table_x = zaws_dynamodb.Table(name="test-db-" + random_str,
                                  session=session,
                                  config=dict(AttributeDefinitions=[dict(AttributeName='id',
                                                                         AttributeType='S')],
                                              KeySchema=[dict(AttributeName='id',
                                                              KeyType='HASH')],
                                              ProvisionedThroughput=dict(
                                                  ReadCapacityUnits=5,
                                                  WriteCapacityUnits=5,
                                              )
                                  ))

    yield table_x

    # don't care about consistency with bucket_x.exists; this is a fixture not a test
    table_x.delete(not_exists_ok=True)


def test_table_creation_and_deletion(my_table, caplog):
    caplog.set_level(logging.CRITICAL)

    assert not my_table.exists
    my_table.put()
    assert my_table.exists
    #assert my_queue._detect_existence_using_index_id()

    arn = my_table.arn
    assert arn
    assert arn.endswith(my_table.name)
    assert arn.startswith('arn:aws')

    my_table.delete()
    my_table.wait_until_not_exists()
    assert not my_table.exists


def test_table_arn(my_table, caplog):
    caplog.set_level(logging.CRITICAL)
    my_table.put()

    arn = my_table.arn
    assert arn
    assert arn.endswith(my_table.name)
    assert arn.startswith('arn:aws')


def test_table_set_and_get(my_table: zaws_dynamodb.Table, caplog):
    caplog.set_level(logging.CRITICAL)
    my_table.put()

    put_resp = my_table.boto3_resource().put_item(Item={'id': '123'})
    print(put_resp)
    query_resp = my_table.boto3_resource().query(
        KeyConditionExpression='#K = :v',
        ExpressionAttributeNames={'#K': 'id'},
        ExpressionAttributeValues={':v': '123'},
    )

    assert 1 <= query_resp['Count']

