import json
import logging
import boto3
import uuid
from functools import partialmethod, partial
from typing import Dict, Iterable, Tuple, Optional, Mapping, Generator, Union
from types import MappingProxyType
from .basic import (AWSResource, scroll, AwaitableAWSResource, standard_tags, manager_tag_key, get_account_id,
                    zsec_tools_manager_tag_value, HasServiceResource)
from toolz import first, thread_last, pipe, merge
from toolz.curried import assoc
import abc
from .meta import apply_with_relevant_kwargs
from .async_tools import map_async

logger = logging.getLogger(__name__)
MAX_POLICY_VERSION_COUNT = 5  # set by Amazon

CREDENTIALS_TEMPLATE = """
[{profile}]
aws_access_key_id = {aws_access_key_id}
aws_secret_access_key = {aws_secret_access_key}
aws_session_token = {aws_session_token}
"""


def assume_role_response_to_session_kwargs(assume_role_resp):
    """Convert assume role response to kwargs for boto3.Session

    Also useful for creating AWS credentials file.

    """
    return dict(aws_access_key_id=assume_role_resp['Credentials']['AccessKeyId'],
                aws_secret_access_key=assume_role_resp['Credentials']['SecretAccessKey'],
                aws_session_token=assume_role_resp['Credentials']['SessionToken'], )


def assume_role_session(session: boto3.Session,
                        RoleArn: str,
                        RoleSessionName: str = 'automation',
                        **kwargs) -> boto3.Session:
    """Get session using assume-role.

    Passes kwargs to sts.assume_role

    To catch AccessDenied::

        try:
            assume_role_session(...)
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "AccessDenied":
                broken_access[account_number] = accounts[account_number]

    """
    resp = session.client('sts').assume_role(
        RoleArn=RoleArn,
        RoleSessionName=RoleSessionName,
        **kwargs)

    return boto3.Session(
        aws_access_key_id=resp['Credentials']['AccessKeyId'],
        aws_secret_access_key=resp['Credentials']['SecretAccessKey'],
        aws_session_token=resp['Credentials']['SessionToken'],
    )


class IAMResource(HasServiceResource, AwaitableAWSResource, AWSResource, abc.ABC):
    service_name: str = 'iam'
    arn_key: str = 'Arn'
    not_found_exception_name = 'NoSuchEntityException'
    tags_key: str = 'Tags'

    def describe(self, **kwargs) -> Dict:
        combined_kwargs = {self.index_id_key: self.index_id}
        combined_kwargs.update(kwargs)
        client_method = getattr(self.service_client, "get_{}".format(self.sdk_name))
        return client_method(**combined_kwargs)[self._description_top_key]

    @property
    def arn(self) -> str:
        return self.boto3_resource().arn

    def put(self, wait: bool = True, force: bool = False):
        if self.exists:
            _, remote_tags = self._get_index_id_and_tags_from_boto3_resource(
                self.boto3_resource(), self.session, self.region_name)
            if force or remote_tags.get(manager_tag_key) == self.manager:
                self.update()
            else:
                raise ValueError("Resource managed by another manager.")
        else:
            logger.info('{} "{}" does not exist. Creating.'.format(self._description_top_key, self.name))
            resp, self.index_id = self.create(wait=wait)
            assert self.index_id  # should always pass for this resource type
            self.exists = True

        assert self.index_id

    @abc.abstractmethod
    def update(self):
        pass


class Policy(IAMResource):
    """
    See also

    - `IAM.Policy`__
    - `IAM.UserPolicy`__

    __ https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#policy
    __ https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#userpolicy

    """
    _description_top_key: str = 'Policy'
    id_key: str = 'PolicyId'
    name_key: str = 'PolicyName'
    sdk_name: str = 'policy'
    index_id_key = 'PolicyArn'
    existence_waiter_name = 'policy_exists'
    tags_key = 'Description'

    def _get_index_id_from_name(self):
        maybe_description = self._get_description_from_name()
        if maybe_description:
            return maybe_description['Arn']

    @classmethod
    def _get_index_id_and_tags_from_boto3_resource(cls, boto3_resource, _, _2) -> Tuple[str, Optional[Dict]]:
        description = boto3_resource.description
        index_id = boto3_resource.arn
        if not description:
            return index_id, None
        try:
            return index_id, json.loads(description)['Tags']
        except (json.JSONDecodeError, KeyError):
            return index_id, None

    def _get_description_from_name(self):
        policies = scroll(self.service_client.list_policies)
        try:
            return first(filter(lambda x: x['PolicyName'] == self.name, policies))
        except StopIteration:
            return None

    def _process_config(self, config: Mapping) -> Mapping:
        tags_dict = merge(standard_tags(self), config.get('Description', {}))
        processed_config = pipe(config,
                                assoc(key='Description', value=tags_dict),
                                super()._process_config)
        return processed_config

    def update(self):
        br_policy = self.boto3_resource()

        # Make room for new version if necessary
        existing_versions = list(br_policy.versions.all())
        if MAX_POLICY_VERSION_COUNT <= len(existing_versions):
            existing_versions[0].delete()

        policy_version = br_policy.create_version(
            PolicyDocument=self.processed_config['PolicyDocument'],
            SetAsDefault=True,
        )

    @property
    def arn(self) -> str:
        return super().arn if self.index_id else "arn:aws:iam::{}:policy{}/{}".format(
            get_account_id(self.session),
            self.processed_config.get('Path', ''),
            self.name, )

    def wait_until_exists(self):
        self.wait(self.existence_waiter_name, PolicyArn=self.arn)

    def delete(self, not_exists_ok: bool = False, **kwargs) -> Optional[Dict]:
        # Make room for new version if necessary
        for version in self.boto3_resource().versions.all():
            if not version.is_default_version:
                version.delete()

        super().delete(not_exists_ok=not_exists_ok, **kwargs)


class Role(IAMResource):
    _description_top_key: str = 'Role'
    id_key: str = 'RoleId'
    name_key: str = 'RoleName'
    sdk_name: str = 'role'
    index_id_key = name_key
    existence_waiter_name = 'role_exists'
    non_creation_parameters = ('Policies', 'InlinePolicies')

    def _get_index_id_from_name(self):
        return self.name

    @classmethod
    def _get_index_id_and_tags_from_boto3_resource(cls, boto3_resource, _, _2) -> Tuple[str, Optional[Dict]]:
        tags = {tag['Key']: tag['Value'] for tag in (boto3_resource.tags or ())}
        return boto3_resource.name, tags

    def _process_config(self, config: Mapping) -> Mapping:
        tags_dict = merge(standard_tags(self), config.get('Tags', {}))
        tags_list = [{'Key': k, 'Value': v} for k, v in tags_dict.items()]
        processed_config = pipe(config,
                                assoc(key='Tags', value=tags_list),
                                super()._process_config)

        # TODO: follow similar processing method as s3 Bucket
        if 'InlinePolicies' in config:
            for inline_policy in config['InlinePolicies']:
                inline_policy['PolicyDocument'] = json.dumps(inline_policy['PolicyDocument'])

        return processed_config

    def create(self, wait: bool = True, **kwargs) -> Tuple[Dict, Optional[str]]:
        result = super().create(wait=wait, **kwargs)
        if 'Policies' in self.processed_config:
            self.put_policies(self.processed_config['Policies'])

        if 'InlinePolicies' in self.processed_config:
            for inline_policy in self.processed_config['InlinePolicies']:
                self.service_client.put_role_policy(**{self.index_id_key: self.index_id,
                                                       **inline_policy})

        return result

    def update(self):
        update_kwargs = dict(self.processed_config)
        update_kwargs['PolicyDocument'] = update_kwargs['AssumeRolePolicyDocument']
        apply_with_relevant_kwargs(self.service_client, self.service_client.update_role,
                                   self.processed_config, ignore_when_missing_required_keys=True)

        apply_with_relevant_kwargs(self.service_client, self.service_client.update_assume_role_policy,
                                   self.processed_config, ignore_when_missing_required_keys=True)

        apply_with_relevant_kwargs(self.service_client, self.service_client.put_role_policy,
                                   self.processed_config, ignore_when_missing_required_keys=True)

        apply_with_relevant_kwargs(self.service_client, self.service_client.tag_role,
                                   self.processed_config, ignore_when_missing_required_keys=True)

        apply_with_relevant_kwargs(self.service_client, self.service_client.put_role_permissions_boundary,
                                   self.processed_config, ignore_when_missing_required_keys=True)

        self.put_policies(self.processed_config['Policies'])

        if 'InlinePolicies' in self.processed_config:
            for inline_policy in self.processed_config['InlinePolicies']:
                self.service_client.put_role_policy(**{self.index_id_key: self.index_id,
                                                       **inline_policy})

    def attach_policy(self, arn):
        self.service_client.attach_role_policy(**{self.name_key: self.name, 'PolicyArn': arn})

    def detach_policy(self, arn):
        self.service_client.detach_role_policy(**{self.name_key: self.name, 'PolicyArn': arn})

    def detach_all_policies(self):
        res = self.boto3_resource()
        for policy in res.attached_policies.all():
            res.detach_policy(PolicyArn=policy.arn)

    def list_role_policies(self):
        # self.service_client.list_role_policies fails to list policies attached to the role, for unknown reasons.
        # use the resource API instead
        # return scroll(self.service_client.list_role_policies, **{self.name_key: self.name})
        res = self.boto3_resource()
        return (Policy(index_id=policy.arn, session=self.session, region_name=self.region_name)
                for policy in res.attached_policies.all())

    def put_policies(self, policies: Iterable[Union[Policy, str]]):
        policy_arns = [policy.arn if isinstance(policy, Policy) else policy  # each policy could be a Policy or arn
                       for policy in policies]
        res = self.boto3_resource()

        wanted = frozenset(policy_arns)
        existing = frozenset(policy.arn for policy in res.attached_policies.all())

        to_detach = existing - wanted
        to_attach = wanted - existing

        for policy_arn in to_detach:
            res.detach_policy(PolicyArn=policy_arn)

        for policy_arn in to_attach:
            res.attach_policy(PolicyArn=policy_arn)
