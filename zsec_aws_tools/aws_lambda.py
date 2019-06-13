import boto3
import logging
from typing import Dict, Union
from .cleaning import clean_up_stack
import io
from .basic import scroll, AWSResource
import zipfile
from pathlib import Path
import hashlib
import hmac


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


class FunctionResource(AWSResource):
    top_key = 'Configuration'
    id_key = 'FunctionArn'
    name_key = 'FunctionName'
    client_name = 'lambda'

    def create(self):
        combined_kwargs = {self.name_key: self.name}
        combined_kwargs.update(self.config)
        return self.service_client.create_function(**combined_kwargs)[self.id_key]

    def _get_id(self, name):
        try:
            return self.describe()[self.id_key]
        except self.service_client.exceptions.ResourceNotFoundException:
            return None

    def delete(self, **kwargs):
        combined_kwargs = {self.name_key: self.name}
        combined_kwargs.update(kwargs)
        self.service_client.delete_function(**combined_kwargs)

    def describe(self, **kwargs):
        combined_kwargs = {self.name_key: self.name}
        combined_kwargs.update(kwargs)
        return self.service_client.get_function(**combined_kwargs)[self.top_key]

    def update(self, **kwargs):
        combined_kwargs = {self.name_key: self.name}
        combined_kwargs.update(kwargs)
        code_kwargs = {k: v for k, v in combined_kwargs.items()
                       if k in update_function_code_input_keys}
        configuration_kwargs = {k: v for k, v in combined_kwargs.items()
                                if k in update_function_configuration_input_keys}
        resp = self.service_client.update_function_code(**code_kwargs)[self.top_key]
        resp.update(self.service_client.update_function_configuration(**configuration_kwargs)[self.top_key])
        return resp

    def put(self, force=False):
        kwargs = self.config
        tags = {'Creator': 'zsec_aws_tools.aws_lambda'}
        tags.update(kwargs.get('Tags', {}))
        kwargs['Tags'] = tags
        kwargs[self.name_key] = self.name

        # Check if function exists, get configuration if it exists. If function does not exist, catch error.
        if self.exists:
            remote_configuration = self.describe()
            arn = remote_configuration['FunctionArn']
            if not force:
                if remote_configuration.get('Tags', {}).get('Creator') != tags['Creator']:
                    raise self.service_client.exceptions.ResourceConflictException(
                        "Resource created by another creator.")

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
            self.service_client.update_function_configuration(**kwargs3)
            self.service_client.tag_resource(Resource=arn, Tags=tags)
        else:
            try:
                logger.info('creating function')
                self.service_client.create_function(**kwargs)
                logger.info('finished creating function')
            except self.service_client.exceptions.ResourceConflictException as error:
                # this should never happen
                logger.error('possible race condition encountered')
                raise
            else:
                raise


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
