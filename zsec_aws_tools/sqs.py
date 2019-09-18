import logging
import io
import uuid
from typing import Dict, Union, Mapping, Generator, Tuple, Optional
from toolz import pipe, merge
from toolz.curried import assoc
from .basic import (scroll, AWSResource, AwaitableAWSResource, manager_tag_key, HasServiceResource,
                    standard_tags)
from pathlib import Path
import time
import boto3
from botocore.exceptions import ClientError
from .iam import Role
import json
from .async_tools import map_async

logger = logging.getLogger(__name__)


"""
NOTE:
QueueUrl looks like this: https://sqs.{region_name}.amazonaws.com/{account_id}/{queue_name}
"""


class Queue(HasServiceResource, AWSResource):
    _description_top_key = 'Queue'
    index_id_key = 'QueueUrl'
    name_key = 'QueueName'
    service_name = 'sqs'
    sdk_name = 'queue'
    not_found_exception_name = 'QueueDoesNotExist'
    non_creation_parameters = ['Tags']

    def _process_config(self, config: Mapping) -> Mapping:
        processed_config = pipe(config,
                                assoc(key='Tags', value=merge(standard_tags(self), config.get('Tags', {}))),
                                # original tags takes precedence if there is a conflict
                                super()._process_config)
        return processed_config

    def _get_index_id_from_name(self):
        sr = self.session.resource(self.service_name)
        try:
            return sr.get_queue_by_name(**{self.name_key: self.name}).url
        except self.service_client.exceptions.QueueDoesNotExist:
            return

    @classmethod
    def _get_index_id_and_tags_from_boto3_resource(cls, boto3_resource, session: boto3.Session, region_name: str) \
            -> Tuple[str, Optional[Dict]]:
        queue_url = boto3_resource.url
        service_client = session.client(cls.service_name, region_name=region_name)
        tags = service_client.list_queue_tags(QueueUrl=queue_url).get('Tags')
        return queue_url, tags

    def describe(self, **kwargs) -> Dict:
        assert self.index_id
        combined_kwargs = {self.index_id_key: self.index_id}
        combined_kwargs.update(kwargs or {'AttributeNames': ['All']})
        return merge(self.service_client.get_queue_attributes(**combined_kwargs),
                     {self.name_key: self.index_id.split('/')[-1]}  # add the name
                     )

    @property
    def arn(self) -> str:
        return self.describe(AttributeNames=['QueueArn'])['Attributes']['QueueArn']

    def put(self, wait: bool = True, force: bool = False):
        if self.exists:
            kwargs = {self.index_id_key: self.index_id,
                      'Attributes': (self.processed_config.get('Attributes', {}))}
            self.service_client.set_queue_attributes(**kwargs)
            self.service_client.tag_queue(QueueUrl=self.index_id, Tags=self.processed_config['Tags'])
        else:
            try:
                logger.info('creating queue')
                self.create(wait=True)
                assert self.index_id
                assert self.exists
                self.service_client.tag_queue(QueueUrl=self.index_id, Tags=self.processed_config['Tags'])
                logger.info('finished creating queue')
            except self.service_client.exceptions.QueueNameExists:
                # this should never happen
                logger.error('possible race condition encountered')
                raise

    def send_message(self, **kwargs):
        """See
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs.html#SQS.Client.send_message
        """
        combined_kwargs = {self.index_id_key: self.index_id}
        combined_kwargs.update(kwargs)
        return self.service_client.send_message(**combined_kwargs)

    def receive_message(self, **kwargs):
        """See
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs.html#SQS.Client.receive_message
        """
        combined_kwargs = {self.index_id_key: self.index_id}
        combined_kwargs.update(kwargs)
        return self.service_client.receive_message(**combined_kwargs)
