import pytest
import boto3
import uuid
import random
import string
import logging
import zsec_aws_tools.s3 as zaws_s3
from zsec_aws_tools.basic import get_account_id


@pytest.fixture
def s3_bucket():
    session = boto3.Session(profile_name='test')

    account_id = get_account_id(session)

    def bucket_policy(bucket: zaws_s3.Bucket):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": account_id
                    },
                    "Action": [
                        "s3:AbortMultipartUpload",
                        "s3:GetBucketLocation",
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:ListBucketMultipartUploads",
                        "s3:PutObject",
                        "s3:PutObjectAcl"
                    ],
                    "Resource": [
                        bucket.arn,
                        "{bucket_arn}/*".format(bucket_arn=bucket.arn),
                    ],
                }
            ]}

    random_str = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))

    bucket_x = zaws_s3.Bucket(session=session, region_name='us-east-1',
                              name='test-bucket-' + random_str,
                              ztid=uuid.UUID('bf981b04-dae1-4b6c-a6c3-0d107eb4c847'),
                              config=dict(ACL='private',
                                          Policy=bucket_policy))

    yield bucket_x

    # don't care about consistency with bucket_x.exists; this is a fixture not a test
    bucket_x.delete(not_exists_ok=True)


def test_s3_bucket(s3_bucket, caplog):
    caplog.set_level(logging.CRITICAL)

    assert not s3_bucket.exists
    s3_bucket.put()
    assert s3_bucket.exists
    assert s3_bucket._detect_existence_using_index_id()

    s3_bucket.delete()
    s3_bucket.wait_until_not_exists()
    assert not s3_bucket.exists
    assert not s3_bucket._detect_existence_using_index_id()

    policy = s3_bucket.boto3_resource().Policy()
    acl = s3_bucket.boto3_resource().Acl()

    #print(acl.grants)


def test_existing_s3_bucket(s3_bucket, caplog):
    s3_bucket.put()

    copy = zaws_s3.Bucket(session=s3_bucket.session, region_name=s3_bucket.region_name,
                          name=s3_bucket.name,
                          ztid=s3_bucket.ztid,
                          config=s3_bucket.config)

    assert copy._get_index_id_from_ztid() == copy.name

    assert copy.exists


def test_list_with_tags(s3_bucket, caplog):
    s3_bucket.put()

    for bucket in zaws_s3.Bucket.list_with_tags(s3_bucket.session):
        assert bucket.ztid != s3_bucket.ztid or bucket.name == s3_bucket.name


def fallback_cleanup_utility():
    """Use this in case testing litters the test account with test buckets"""
    service_resource = boto3.Session(profile_name='test').resource('s3')
    for bucket in service_resource.buckets.all():
        if bucket.name.startswith('test-bucket-'):
            print(bucket.name)
            bucket.delete()
