import logging
from typing import Dict, Union, Mapping, Generator, Tuple, Optional
from toolz import pipe, merge
from toolz.curried import assoc

from zsec_aws_tools.meta import apply_with_relevant_kwargs
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


class Table(HasServiceResource, AWSResource):
    top_key = 'Table'
    index_id_key = 'TableName'
    name_key = 'TableName'
    service_name = 'dynamodb'
    sdk_name = 'table'
    #not_found_exception_name = 'TableNotFoundException'
    not_found_exception_name = 'ResourceNotFoundException'
    # non_creation_parameters = ['Tags']

    def _process_config(self, config: Mapping) -> Mapping:
        tags = [{'Key': k, 'Value': v} for k, v in merge(standard_tags(self), config.get('Tags', {})).items()]

        processed_config = pipe(config,
                                assoc(key='Tags', value=tags),
                                # original tags takes precedence if there is a conflict
                                super()._process_config)
        return processed_config

    def _get_index_id_from_name(self) -> Optional[str]:
        raise ValueError('Should not be called')

    @classmethod
    def _get_index_id_and_tags_from_boto3_resource(cls, boto3_resource, session: boto3.Session, region_name: str) \
            -> Tuple[str, Optional[Dict]]:
        service_client = session.client(cls.service_name, region_name=region_name)
        tags = (service_client
                .get_paginator('service_client.list_tags_of_resource')
                .paginate(ResourceArn=boto3_resource.table_arn)
                .get('Tags'))
        return boto3_resource.table_name, {tt['Key']: tt['Value'] for tt in tags}

    def describe(self, **kwargs) -> Dict:
        return self.service_client.describe_table(**{self.index_id_key: self.index_id})['Table']

    def wait_until_exists(self) -> None:
        self.boto3_resource().wait_until_exists()

    def wait_until_not_exists(self) -> None:
        self.boto3_resource().wait_until_not_exists()

    @property
    def arn(self) -> str:
        return self.boto3_resource().table_arn

    def put(self, wait: bool = True, force: bool = False):
        kwargs = {self.index_id_key: self.index_id, **self.processed_config}

        if self.exists:
            apply_with_relevant_kwargs(self.service_client, self.service_client.update_table, kwargs)
            apply_with_relevant_kwargs(self.service_client, self.service_client.tag_resource,
                                       {'ResourceArn': self.arn, **kwargs})
        else:
            try:
                logger.info(f'creating f{self.sdk_name}')
                self.create(wait=True)
                assert self.index_id
                assert self.exists
                apply_with_relevant_kwargs(self.service_client, self.service_client.tag_resource,
                                           {'ResourceArn': self.arn, **kwargs})
                logger.info(f'finished creating {self.sdk_name}')
            except self.service_client.exceptions.TableAlreadyExistsException:
                # this should never happen
                logger.error('possible race condition encountered')
                raise