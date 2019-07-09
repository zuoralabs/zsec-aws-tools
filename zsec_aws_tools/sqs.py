import logging
import io
import uuid
from typing import Dict, Union, Mapping, Generator
from toolz import pipe, merge
from toolz.curried import assoc
from .basic import (scroll, AWSResource, AwaitableAWSResource, manager_tag_key,
                    standard_tags)
from pathlib import Path
import time
from botocore.exceptions import ClientError
from .iam import Role
import json
from .async_tools import map_async

logger = logging.getLogger(__name__)


"""
NOTE:
QueueUrl looks like this: https://sqs.{region_name}.amazonaws.com/{account_id}/{queue_name}
"""


class Queue(AWSResource):
    top_key = 'Queue'
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
        for queue_url in scroll(self.service_client.list_queues, QueueNamePrefix=self.name, resp_key='QueueUrls'):
            if queue_url.split('/')[-1] == self.name:
                return queue_url

    @classmethod
    def list_with_tags(cls, session, region_name=None, sync=False) -> Generator['Queue', None, None]:
        service_client = session.client(cls.service_name, region_name=region_name)

        def resource_with_tags(queue_url):
            tags = service_client.list_queue_tags(QueueUrl=queue_url)['Tags']

            return Queue(session=session,
                         region_name=region_name,
                         ztid=pipe(tags.get('ztid'), lambda x: uuid.UUID(x) if x else None),
                         index_id=queue_url,
                         config={'Tags': tags},
                         assume_exists=True)

        return map_async(resource_with_tags, scroll(service_client.list_queues), sync=sync)

    def describe(self, **kwargs) -> Dict:
        assert self.index_id
        combined_kwargs = {self.index_id_key: self.index_id}
        combined_kwargs.update(kwargs or {'AttributeNames': ['All']})
        return self.service_client.get_queue_attributes(**combined_kwargs)

    @property
    def arn(self) -> str:
        return self.describe(AttributeNames=['QueueArn'])['Attributes']['QueueArn']

    def put(self, wait: bool = True, force: bool = False):
        if self.exists:
            kwargs = {self.index_id_key: self.index_id,
                      'Attributes': (self.processed_config.get('Attributes', {}))}
            self.service_client.set_queue_attributes(**kwargs)
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
