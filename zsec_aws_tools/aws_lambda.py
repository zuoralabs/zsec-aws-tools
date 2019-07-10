import logging
import io
import uuid
from typing import Dict, Union, Mapping, Generator
from toolz import pipe, merge
from toolz.curried import assoc
from .basic import (scroll, AWSResource, AwaitableAWSResource, manager_tag_key,
                    standard_tags)
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


class FunctionResource(AwaitableAWSResource, AWSResource):
    top_key = 'Function'
    id_key = 'FunctionArn'
    name_key = 'FunctionName'
    service_name = 'lambda'
    sdk_name = 'function'
    index_id_key = name_key
    not_found_exception_name = 'ResourceNotFoundException'
    role: Role
    existence_waiter_name = 'function_exists'
    non_creation_parameters = ['Permissions']

    def _process_config(self, config: Mapping) -> Mapping:
        self.role = role = config['Role']
        assert isinstance(self.role, Role)

        processed_config = pipe(config,
                                assoc(key='Role', value=role.arn),
                                assoc(key='Tags', value=merge(standard_tags(self), config.get('Tags', {}))),
                                # original tags takes precedence if there is a conflict
                                super()._process_config)

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
            remote_tags = remote_description['Tags']
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

        for permission in self.config.get('Permissions', ()):
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
    import os

    with zipfile.ZipFile(output, 'w') as zf:
        if source.is_dir():
            for dd, _, ffs in os.walk(str(source)):
                for ff in ffs:
                    pp = Path(dd, ff)
                    zf.write(pp, arcname=pp.relative_to(Path('src')))
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
