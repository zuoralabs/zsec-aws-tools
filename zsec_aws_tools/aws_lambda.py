import logging
from typing import Dict, Union
import io
from .basic import scroll, AWSResource, get_index_id_from_description, AwaitableAWSResource
import zipfile
from pathlib import Path
import hashlib
import hmac
import time
from botocore.exceptions import ClientError
from .iam import Role
import json

zsec_tools_manager_tag_value = 'zsec_aws_tools.aws_lambda'
manager_tag_key = 'Manager'

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
    client_name = 'lambda'
    sdk_name = 'function'
    index_id_key = name_key
    not_found_exception_name = 'ResourceNotFoundException'
    role: Role
    waiter_name = 'function_exists'

    def _process_config(self):
        self.role = role = self.config['Role']
        assert isinstance(self.role, Role)
        role_arn = role.describe()[role.arn_key]
        self.config['Role'] = role_arn

        # Set default Manager tag if it doesn't exist.
        tags = {manager_tag_key: zsec_tools_manager_tag_value}  # defaults
        tags.update(self.config.get('Tags', {}))
        self.config['Tags'] = tags

        super()._process_config()

    def _get_index_id_from_name(self):
        return get_index_id_from_description(self)

    def _just_need_to_wait(self, err):
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
                        for statement in json.loads(self.role.config['AssumeRolePolicyDocument'])['Statement']))

    def describe(self, **kwargs) -> Dict:
        combined_kwargs = {self.index_id_key: self.index_id}
        combined_kwargs.update(kwargs)
        return self.service_client.get_function(**combined_kwargs)

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

    def put(self, wait: bool, force: bool = False):
        if self.exists:
            kwargs = self.config
            remote_description = self.describe()
            remote_tags = remote_description['Tags']
            remote_configuration = remote_description['Configuration']
            arn = remote_configuration['FunctionArn']

            tags = self.config['Tags']

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
            except self.service_client.exceptions.ResourceConflictException as error:
                # this should never happen
                logger.error('possible race condition encountered')
                raise

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
            for dd, _, ffs in os.walk(source):
                for ff in ffs:
                    pp = Path(dd, ff)
                    zf.write(pp, arcname=pp.relative_to(Path('src')))
        else:
            zf.write(source, arcname=str(source))
