import json
import logging
import botocore.exceptions
from typing import Optional, Dict, Mapping
from toolz import merge, pipe
from toolz.curried import assoc
from .basic import (scroll, AWSResource, AwaitableAWSResource, standard_tags)

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
    non_creation_parameters = ['Policy', 'Tags']

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

    def _get_index_id_from_ztid(self) -> Optional[str]:
        resource_client = self.session.resource(self.client_name, region_name=self.region_name)
        for bucket in resource_client.buckets.all():
            try:
                tag_set = bucket.Tagging().tag_set
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchTagSet':
                    continue
                else:
                    raise
            else:
                for ztid in (ts['Value'] for ts in tag_set if ts['Key'] == 'ztid'):
                    if ztid == self.ztid:
                        return bucket.name
                else:
                    continue

    def _process_config(self, config: Mapping) -> Mapping:
        tags_dict = merge(standard_tags(self.ztid), config.get('Tags', {}))
        tags_list = [{'Key': k, 'Value': v} for k, v in tags_dict.items()]
        processed_config = pipe(config,
                                assoc(key='Tags', value=tags_list),
                                super()._process_config)
        return processed_config

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
            self.create(wait=wait)   # no need to set index_id since `self.index_id_key == self.name_key`
            self.exists = True

        if 'Policy' in self.processed_config:
            policy = json.dumps(self.processed_config['Policy'](self))
            self.boto3_resource().Policy().put(Policy=policy)

        if 'Tags' in self.processed_config:
            tags = self.processed_config['Tags']
            self.boto3_resource().Tagging().put(Tagging={'TagSet': tags})

    def wait_until_not_exists(self) -> None:
        return self.boto3_resource().wait_until_not_exists()

    @property
    def arn(self):
        return 'arn:aws:s3:::' + self.name
