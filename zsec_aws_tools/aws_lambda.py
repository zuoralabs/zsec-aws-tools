import logging
import io
import uuid
from typing import Dict, Union, Mapping, Generator, Optional
from toolz import pipe, merge, identity
from toolz.curried import assoc

from .basic import (scroll, AWSResource, AwaitableAWSResource, manager_tag_key,
                    standard_tags, get_account_id)
from .meta import get_operation_model, apply_with_relevant_kwargs
import zipfile
from pathlib import Path
import hashlib
import hmac
import time
from botocore.exceptions import ClientError
from .iam import Role
import json
from .async_tools import map_async

logger = logging.getLogger(__name__)

# list(get_operation_model(aws_lambda, 'update_function_configuration' ).input_shape.members.keys())
update_function_configuration_input_keys = ['FunctionName',
                                            'Role',
                                            'Handler',
                                            'Description',
                                            'Timeout',
                                            'MemorySize',
                                            'VpcConfig',
                                            'Environment',
                                            'Runtime',
                                            'DeadLetterConfig',
                                            'KMSKeyArn',
                                            'TracingConfig',
                                            'RevisionId',
                                            'Layers']

# list(get_operation_model(aws_lambda, 'update_function_code' ).input_shape.members.keys())
update_function_code_input_keys = ['FunctionName',
                                   'ZipFile',
                                   'S3Bucket',
                                   'S3Key',
                                   'S3ObjectVersion',
                                   'Publish',
                                   'DryRun',
                                   'RevisionId']


class ConfigArgumentModel:
    sdk_name: str
    create_name: str
    delete_name: str
    update_name: Optional[str]
    is_collection: bool

    def __init__(self, sdk_name, create_name='create', delete_name='delete', update_name: Optional[str] = 'update',
                 is_collection: bool = False):
        self.sdk_name = sdk_name
        self.create_name = create_name
        self.delete_name = delete_name
        self.update_name = update_name
        self.is_collection = is_collection


class FunctionResource(AwaitableAWSResource, AWSResource):
    """
    WARNING: Permissions do not behave as expected, since AWS API has no documented way of checking for
    existing permissions. That means you have to explicitly remove unwanted permissions by StatementId.
    """
    _description_top_key = 'Function'
    id_key = 'FunctionArn'
    name_key = 'FunctionName'
    service_name = 'lambda'
    sdk_name = 'function'
    index_id_key = name_key
    not_found_exception_name = 'ResourceNotFoundException'
    role: Role
    existence_waiter_name = 'function_exists'
    non_creation_parameters = {
        'Permissions': ConfigArgumentModel('permission', create_name='add', delete_name='remove',
                                           update_name=None, is_collection=True),
        'EventSourceMappings': ConfigArgumentModel('event_source_mapping', is_collection=True),
    }

    def _process_config(self, config: Mapping) -> Mapping:
        self.role = role = config.get('Role')
        assert role is None or isinstance(self.role, Role)

        processed_config = pipe(config,
                                assoc(key='Role', value=role.arn) if role else identity,
                                assoc(key='Tags', value=merge(standard_tags(self), config.get('Tags', {}))),
                                # original tags takes precedence if there is a conflict
                                super()._process_config,
                                dict)

        for config_key, model in self.non_creation_parameters.items():
            if config_key in processed_config:
                operation_name = getattr(self.service_client, model.create_name + '_' + model.sdk_name)
                operation_model = get_operation_model(self.service_client, operation_name)
                value = self._process_config_value(None, processed_config[config_key])

                if model.is_collection:
                    processed_value = [self._process_config_value(operation_model.input_shape, elt)
                                       for elt in value]
                else:
                    processed_value = self._process_config_value(operation_model.input_shape.members[config_key],
                                                                 processed_config[config_key])

                processed_config[config_key] = processed_value

        return processed_config

    def _get_index_id_from_name(self):
        return self.name

    @classmethod
    def list_with_tags(cls, session, region_name=None, sync=False) -> Generator['FunctionResource', None, None]:
        service_client = session.client(cls.service_name, region_name=region_name)

        def resource_with_tags(description):
            tags = description.get('Tags',
                                   service_client.list_tags(Resource=description['FunctionArn'])['Tags'])

            return FunctionResource(session=session,
                                    region_name=region_name,
                                    ztid=pipe(tags.get('ztid'), lambda x: uuid.UUID(x) if x else None),
                                    index_id=description[cls.index_id_key],
                                    config={'Tags': tags},
                                    assume_exists=True)

        return map_async(resource_with_tags, scroll(service_client.list_functions), sync=sync)

    def _just_need_to_wait(self, err) -> bool:
        """Determines if we got a real error or if we just need to wait and retry

        See
        - https://stackoverflow.com/questions/36419442/the-role-defined-for-the-function-cannot-be-assumed-by-lambda
        - https://stackoverflow.com/questions/37503075/invalidparametervalueexception-the-role-defined-for-the-function-cannot-be-assu

        """

        return (err.response['Error']['Code'] in ('InvalidParameterValueException', 'AccessDeniedException')
                and err.response['Error']['Message'] == 'The role defined for the function cannot be assumed by Lambda.'
                and any((statement['Effect'] == 'Allow'
                         and statement['Principal'].get('Service') == "lambda.amazonaws.com"
                         and statement['Action'] == "sts:AssumeRole")
                        for statement in
                        json.loads(self.role.processed_config['AssumeRolePolicyDocument'])['Statement']))

    def describe(self, **kwargs) -> Dict:
        combined_kwargs = {self.index_id_key: self.index_id}
        combined_kwargs.update(kwargs)
        return self.service_client.get_function(**combined_kwargs)

    @property
    def arn(self) -> str:
        return self.describe()['Configuration']['FunctionArn']

    def construct_arn(self):
        """Construct arn without needing for the resource to exist"""
        return 'arn:aws:lambda:{region_name}:{account}:function:{name}'.format(
            region_name=self.region_name or self.session.region_name,
            account=get_account_id(self.session),
            name=self.name)

    def create(self, wait: bool = True, **kwargs) -> str:
        while True:
            try:
                super().create(wait=wait, **kwargs)
            except ClientError as err:
                if self._just_need_to_wait(err):
                    logger.info('Failure {}; need to wait'.format(err.operation_name))
                    time.sleep(1)
                else:
                    raise
            else:
                break
        return self.name

    def put(self, wait: bool = True, force: bool = False):
        if self.exists:
            kwargs = self.processed_config
            remote_description = self.describe()
            remote_tags = remote_description.get('Tags', {})
            remote_configuration = remote_description['Configuration']
            arn = remote_configuration['FunctionArn']

            tags = self.processed_config['Tags']

            if not force:
                if remote_tags.get(manager_tag_key) != tags[manager_tag_key]:
                    raise ValueError("Resource managed by another manager.")

            remote_sha = remote_configuration['CodeSha256']

            if 'ZipFile' in kwargs['Code']:
                hh = hashlib.sha256(kwargs['Code']['ZipFile'])
                local_sha = hh.hexdigest()
                need_update = not hmac.compare_digest(local_sha, remote_sha)
            else:
                need_update = True

            if need_update:
                kwargs2 = {}
                kwargs2.update(kwargs['Code'])
                kwargs2.update({k: v for k, v in kwargs.items() if
                                k in {'FunctionName', 'Publish', 'DryRun', 'RevisionId'}})
                self.service_client.update_function_code(**kwargs2)
                logger.info('updated function')

            kwargs3 = {}
            kwargs3.update({k: v for k, v in kwargs.items() if k in update_function_configuration_input_keys})
            while True:
                try:
                    self.service_client.update_function_configuration(**kwargs3)
                    self.service_client.tag_resource(Resource=arn, Tags=tags)
                except ClientError as err:
                    if self._just_need_to_wait(err):
                        logger.info('Failure {}; need to wait'.format(err.operation_name))
                        time.sleep(1)
                    else:
                        raise
                else:
                    break
        else:
            try:
                logger.info('creating function')
                self.create(wait=wait)
                logger.info('finished creating function')
            except self.service_client.exceptions.ResourceConflictException:
                # this should never happen
                logger.error('possible race condition encountered')
                raise

        for permission in self.processed_config.get('Permissions', ()):
            try:
                self.service_client.remove_permission(
                    **{self.name_key: self.name,
                       'StatementId': permission['StatementId']}
                )
            except self.service_client.exceptions.ResourceNotFoundException:
                pass
            self.service_client.add_permission(
                **{self.name_key: self.name,
                   **permission}
            )

        for event_source_mapping, extant_esm in \
                self._find_event_source_mappings(self.processed_config.get('EventSourceMappings', ())):
            if event_source_mapping is None:
                self.service_client.delete_event_source_mapping(UUID=extant_esm['UUID'])
            elif extant_esm is not None:
                apply_with_relevant_kwargs(self.service_client, self.service_client.update_event_source_mapping,
                                           {self.name_key: self.name, 'UUID': extant_esm['UUID'],
                                            **event_source_mapping})
            else:
                self.service_client.create_event_source_mapping(
                    **{self.name_key: self.name, **event_source_mapping}
                )

    def _find_event_source_mappings(self, event_source_mappings):
        extant = list(scroll(self.service_client.list_event_source_mappings, **{self.name_key: self.name}))
        to_keep = set()
        for event_source_mapping in event_source_mappings:
            for esm_2 in extant:
                if (esm_2['EventSourceArn'] == event_source_mapping['EventSourceArn']
                        and esm_2['State'] not in ['Deleting']):  # ['Disabling', 'Disabled', ]
                    yield event_source_mapping, esm_2
                    to_keep.add(esm_2['UUID'])
                    break
            else:
                yield event_source_mapping, None

        for esm_2 in extant:
            if esm_2['UUID'] not in to_keep:
                yield None, esm_2

    def invoke(self, json_codec: bool = False, **kwargs):
        if json_codec and 'Payload' in kwargs:
            kwargs['Payload'] = json.dumps(kwargs['Payload']).encode()

        while True:
            try:
                resp = self.service_client.invoke(**{self.index_id_key: self.index_id, **kwargs})
            except ClientError as err:
                if self._just_need_to_wait(err):
                    logger.info('Failure {}; need to wait'.format(err.operation_name))
                    time.sleep(1)
                else:
                    raise
            else:
                break

        if json_codec:
            return json.loads(resp['Payload'].read().decode())
        else:
            return resp


def zip_compress(source: Path, output: Union[Path, io.IOBase]) -> None:
    """
    Usually you will want to create a directory structure:

      - top_level_module
        - lambda_function.py
        - library
          - __init__.py
          - etc.py

    If you want to deploy code to an existing function, your code would look like::

        from zsec_aws_tools import aws_lambda as zaws_lambda
        import boto3
        from pathlib import Path

        src_file = Path('test_deploy')
        zip_file = src_file.with_suffix('.zip')
        zaws_lambda.zip_compress(src_file, zip_file)

        zaws_lambda.FunctionResource(
                session=boto3.Session(region_name='us-west-2'),
                name='test_deploy',
                role='test_role',
                config=dict(
                    Code={'ZipFile': zip_file.read_bytes()},
                    )
                ).put(force=True)

    """
    import os

    with zipfile.ZipFile(output, 'w') as zf:
        if source.is_dir():
            for dd, _, ffs in os.walk(str(source)):
                for ff in ffs:
                    pp = Path(dd, ff)
                    zf.write(pp, arcname=pp.relative_to(source))
        else:
            zf.write(source, arcname=str(source))


default_assume_role_policy_document_for_lambda = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
