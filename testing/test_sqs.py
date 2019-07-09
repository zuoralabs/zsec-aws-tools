import string
import random
import boto3
import pytest
import zsec_aws_tools.sqs as zaws_sqs
import logging


@pytest.fixture
def my_queue():
    session = boto3.Session(profile_name='test', region_name='us-east-1')

    random_str = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))

    queue_x = zaws_sqs.Queue(name="test-queue" + random_str,
                             session=session,
                             config=dict(Attributes=dict(
                                 # fifo_queue                  = true
                                 # content_based_deduplication = true
                                 KmsMasterKeyId="alias/aws/sqs",
                                 KmsDataKeyReusePeriodSeconds=300,
                                 VisibilityTimeout=310,  # needs to be greater than function timeout
                             )))

    yield queue_x

    # don't care about consistency with bucket_x.exists; this is a fixture not a test
    queue_x.delete(not_exists_ok=True)


def test_queue_creation_and_deletion(my_queue, caplog):
    caplog.set_level(logging.CRITICAL)

    assert not my_queue.exists
    my_queue.put()
    assert my_queue.exists
    #assert my_queue._detect_existence_using_index_id()

    arn = my_queue.arn
    assert arn
    assert arn.endswith(my_queue.name)
    assert arn.startswith('arn:aws')

    my_queue.delete()
    assert not my_queue.exists


def test_queue_arn(my_queue, caplog):
    caplog.set_level(logging.CRITICAL)
    my_queue.put()

    arn = my_queue.arn
    assert arn
    assert arn.endswith(my_queue.name)
    assert arn.startswith('arn:aws')


def test_queue_send_and_receive(my_queue, caplog):
    caplog.set_level(logging.CRITICAL)
    my_queue.put()

    body = 'test message body'

    send_resp = my_queue.send_message(MessageBody=body)
    recv_resp = my_queue.receive_message()['Messages']
    assert 1 <= len(recv_resp)

    assert any(send_resp['MD5OfMessageBody'] == received_message['MD5OfBody']
               and send_resp['MessageId'] == received_message['MessageId']
               and received_message['Body'] == body
               for received_message in recv_resp)
