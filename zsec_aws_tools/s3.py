from typing import Optional, Dict
import logging
from .basic import (scroll, AWSResource, AwaitableAWSResource, manager_tag_key,
                    add_manager_tags, add_ztid_tags)
import botocore.exceptions
import json

logger = logging.getLogger(__name__)


class Bucket(AwaitableAWSResource, AWSResource):
    top_key = 'Bucket'
    id_key = 'Bucket'
    name_key = 'Bucket'
    client_name = 's3'
    sdk_name = 'bucket'
    index_id_key = name_key
    not_found_exception_name = 'NoSuchBucket'
    existence_waiter_name = 'bucket_exists'
    non_creation_parameters = ['Policy']

    def _detect_existence_using_index_id(self) -> bool:
        return self.boto3_resource().creation_date is not None

    def _detect_existence_using_index_id_broken(self) -> bool:
        """Broken implementation that uses recommended HeadBucket

        HeadBucket is recommended by AWS to check existence, but it seems to be buggy.
        This implementation is kept as a reference

        """
        try:
            return self.index_id_key in self.service_client.head_bucket(Bucket=self.index_id)
        except botocore.exceptions.ClientError as err:
            # This seems to be a bug with IAM.
            if err.response['Error'] == {'Code': '404', 'Message': 'Not Found'}:
                raise

    def _get_index_id_from_name(self) -> Optional[str]:
        """Return ID using self.name

        Requires that self.name is set and that it is unique.
        Should only be called during `__init__` to set `self.id_`.

        """
        return self.name

    def describe(self) -> Dict:
        """
        Do not call describe on a bucket. It doesn't do anything.
        """
        raise NotImplementedError

    def boto3_resource(self):
        return self.session.resource('s3').Bucket(self.name)

    def put(self, wait: bool = True, force: bool = False):
        if not self.exists:
            logger.info('{} "{}" does not exist. Creating.'.format(self.top_key, self.name))
            resp, _ = self.create(wait=wait)   # no index_id returned by CreateBucket.
            self.exists = True

        if 'Policy' in self.processed_config:
            policy = json.dumps(self.processed_config['Policy'](self))
            self.boto3_resource().Policy().put(Policy=policy)

    def wait_until_not_exists(self) -> None:
        return self.boto3_resource().wait_until_not_exists()

    @property
    def arn(self):
        return 'arn:aws:s3:::' + self.name
