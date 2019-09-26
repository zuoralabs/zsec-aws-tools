import json
import logging
import botocore.exceptions
from typing import Optional, Dict, Mapping, Generator, Tuple
from toolz import merge, pipe, partial
from toolz.curried import assoc
import uuid
from .basic import (scroll, AWSResource, AwaitableAWSResource, standard_tags, HasServiceResource)
from .meta import get_operation_model
from .async_tools import map_async

logger = logging.getLogger(__name__)

bucket_properties = [('ServerSideEncryptionConfiguration', 'encryption'),
                     ('LifecycleConfiguration', 'lifecycle_configuration'),
                     ('BucketLoggingStatus', 'logging'),
                     ('CORSConfiguration', 'cors'),
                     ('NotificationConfiguration', 'notification_configuration'),
                     ]


class Bucket(HasServiceResource, AwaitableAWSResource, AWSResource):
    _description_top_key = 'Bucket'
    id_key = 'Bucket'
    name_key = 'Bucket'
    service_name = 's3'
    sdk_name = 'bucket'
    index_id_key = name_key
    not_found_exception_name = 'NoSuchBucket'
    existence_waiter_name = 'bucket_exists'
    non_creation_parameters = ['Policy', 'Tags', 'ServerSideEncryptionConfiguration', 'LifecycleConfiguration',
                               'BucketLoggingStatus', 'CORSConfiguration', 'NotificationConfiguration',
                               ]
    
    non_creation_parameter_handlers = [
        'put_bucket_' + sdk_name
        for _, sdk_name in bucket_properties
    ]

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

    @classmethod
    def _get_index_id_and_tags_from_boto3_resource(cls, boto3_resource, _, _2) -> Tuple[str, Optional[Dict]]:
        try:
            tag_set = boto3_resource.Tagging().tag_set
        except botocore.exceptions.ClientError as ex:
            if ex.response['Error']['Code'] in (
                    'NoSuchTagSet',
                    'NoSuchBucket',  # We don't manage all buckets, so expect buckets to disappear any time.
            ):
                return boto3_resource.name, None
            else:
                raise
        else:
            tags = {ts['Key']: ts['Value'] for ts in tag_set}
            return boto3_resource.name, tags

    def _process_config(self, config: Mapping) -> Mapping:
        tags_dict = merge(standard_tags(self), config.get('Tags', {}))
        tags_list = [{'Key': k, 'Value': v} for k, v in tags_dict.items()]
        processed_config = pipe(
            config,
            assoc(key='Tags', value=tags_list),
            super()._process_config,
        )
        return processed_config

    def describe(self) -> Dict:
        """
        Do not call describe on a bucket. It doesn't do anything.
        """
        raise NotImplementedError

    def put(self, wait: bool = True, force: bool = False):
        if not self.exists:
            logger.info('{} "{}" does not exist. Creating.'.format(self._description_top_key, self.name))
            self.create(wait=wait)  # no need to set index_id since `self.index_id_key == self.name_key`
            self.exists = True

        if 'Policy' in self.processed_config:
            policy = json.dumps(self.processed_config['Policy'](self))
            self.boto3_resource().Policy().put(Policy=policy)

        if 'Tags' in self.processed_config:
            tags = self.processed_config['Tags']
            self.boto3_resource().Tagging().put(Tagging={'TagSet': tags})

        for config_key, sdk_name in bucket_properties:
            if config_key in self.processed_config:
                getattr(self.service_client, 'put_bucket_' + sdk_name)(
                    **{self.index_id_key: self.index_id,
                       config_key: self.processed_config[config_key]})

    def wait_until_not_exists(self) -> None:
        return self.boto3_resource().wait_until_not_exists()

    @property
    def arn(self):
        return 'arn:aws:s3:::' + self.name
