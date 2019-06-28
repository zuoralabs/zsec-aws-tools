import json
import logging
import boto3
from typing import Dict, Iterable, Tuple, Optional, Mapping
from types import MappingProxyType
from .basic import AWSResource, scroll, AwaitableAWSResource, standard_tags, manager_tag_key, get_account_id
from toolz import first, thread_last, pipe, merge
from toolz.curried import assoc
import abc
from .meta import apply_with_relevant_kwargs

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
    return dict(aws_access_key_id = assume_role_resp['Credentials']['AccessKeyId'],
                aws_secret_access_key = assume_role_resp['Credentials']['SecretAccessKey'],
                aws_session_token = assume_role_resp['Credentials']['SessionToken'],)


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
        aws_access_key_id = resp['Credentials']['AccessKeyId'],
        aws_secret_access_key = resp['Credentials']['SecretAccessKey'],
        aws_session_token = resp['Credentials']['SessionToken'],
    )


class IAMResource(AwaitableAWSResource, AWSResource, abc.ABC):
    client_name: str = 'iam'
    arn_key: str = 'Arn'
    not_found_exception_name = 'NoSuchEntityException'
    tags_key: str = 'Tags'

    def describe(self, **kwargs) -> Dict:
        combined_kwargs = {self.index_id_key: self.index_id}
        combined_kwargs.update(kwargs)
        client_method = getattr(self.service_client, "get_{}".format(self.sdk_name))
        return client_method(**combined_kwargs)[self.top_key]

    @property
    def arn(self) -> str:
        return self.boto3_resource().arn

    def put(self, wait: bool = True, force: bool = False):
        if self.exists:
            remote_description = self.describe()
            remote_tags = {tag['Key']: tag['Value'] for tag in remote_description.get('Tags', ())}

            raw_tags = self.processed_config[self.tags_key]

            if isinstance(raw_tags, dict):
                tags = {tag['Key']: tag['Value'] for tag in raw_tags}
            elif isinstance(raw_tags, str):
                tags = json.loads(raw_tags)
            else:
                raise TypeError

            if not force:
                if remote_tags.get(manager_tag_key) != tags[manager_tag_key]:
                    raise ValueError("Resource managed by another manager.")

            self.update()
        else:
            logger.info('{} "{}" does not exist. Creating.'.format(self.top_key, self.name))
            resp, self.index_id = self.create(wait=wait)
            assert self.index_id  # should always pass for this resource type
            self.exists = True

        assert self.index_id

    def boto3_resource(self):
        cls = getattr(self.session.resource(self.client_name), self.top_key)
        return cls(self.index_id)

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
    top_key: str = 'Policy'
    id_key: str = 'PolicyId'
    name_key: str = 'PolicyName'
    sdk_name: str = 'policy'
    index_id_key = 'PolicyArn'
    existence_waiter_name = 'policy_exists'
    tags_key = 'Description'

    def _get_index_id_from_name(self):
        maybe_dsecription = self._get_description_from_name()
        if maybe_dsecription:
            return maybe_dsecription['Arn']

    def _get_index_id_from_ztid(self):
        service_resource = self.session.resource(self.client_name, region_name=self.region_name)
        for br_policy in service_resource.policies.all():
            #scroll(self.service_client.list_policies, Scope='Local')
            description = br_policy.description
            if description:
                tags = json.loads(description).get(self.tags_key, {})
                if tags.get('ztid') == self.ztid:
                    return br_policy.arn

    def _get_description_from_name(self):
        policies = scroll(self.service_client.list_policies)
        try:
            return first(filter(lambda x: x['PolicyName'] == self.name, policies))
        except StopIteration:
            return None

    def _process_config(self, config: Mapping) -> Mapping:
        tags_dict = merge(standard_tags(self.ztid), config.get('Description', {}))
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
        return super().arn or "arn:aws:iam::{}:policy{}/{}".format(
            get_account_id(self.session),
            self.processed_config.get('Path', ''),
            self.name,)

    def wait_until_exists(self):
        self.wait(self.existence_waiter_name, PolicyArn=self.arn)

    def delete(self, not_exists_ok: bool = False, **kwargs) -> Optional[Dict]:
        # Make room for new version if necessary
        for version in self.boto3_resource().versions.all():
            if not version.is_default_version:
                version.delete()

        super().delete(not_exists_ok=not_exists_ok, **kwargs)


class Role(IAMResource):
    top_key: str = 'Role'
    id_key: str = 'RoleId'
    name_key: str = 'RoleName'
    sdk_name: str = 'role'
    index_id_key = name_key
    existence_waiter_name = 'role_exists'
    non_creation_parameters = ('Policies',)

    def _get_index_id_from_name(self):
        return self.name

    def _get_index_id_from_ztid(self):
        for description in scroll(self.service_client.list_roles):
            tags = description['Tags']
            if tags.get('ztid') == self.ztid:
                return description[self.index_id_key]

    def _process_config(self, config: Mapping) -> Mapping:
        tags_dict = merge(standard_tags(self.ztid), config.get('Tags', {}))
        tags_list = [{'Key': k, 'Value': v} for k, v in tags_dict.items()]
        processed_config = pipe(config,
                                assoc(key='Tags', value=tags_list),
                                super()._process_config)
        return processed_config

    def create(self, wait: bool = True, **kwargs) -> Tuple[Dict, Optional[str]]:
        result = super().create(wait=wait, **kwargs)
        if 'Policies' in self.processed_config:
            self.put_policies(self.processed_config['Policies'])
        return result

    def update(self):
        update_kwargs = dict(self.processed_config)
        update_kwargs['PolicyDocument'] = update_kwargs['AssumeRolePolicyDocument']
        apply_with_relevant_kwargs(self.service_client, self.service_client.update_role,
                                   self.processed_config, ignore_when_missing_required_keys=True)

        apply_with_relevant_kwargs(self.service_client, self.service_client.update_assume_role_policy,
                                   self.processed_config, ignore_when_missing_required_keys=True)

        apply_with_relevant_kwargs(self.service_client, self.service_client.tag_role,
                                   self.processed_config, ignore_when_missing_required_keys=True)

        apply_with_relevant_kwargs(self.service_client, self.service_client.put_role_permissions_boundary,
                                   self.processed_config, ignore_when_missing_required_keys=True)

        self.put_policies(self.processed_config['Policies'])

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
        #return scroll(self.service_client.list_role_policies, **{self.name_key: self.name})
        res = self.boto3_resource()
        return (Policy(index_id=policy.arn, session=self.session, region_name=self.region_name)
                for policy in res.attached_policies.all())

    def put_policies(self, policies: Iterable[Policy]):
        res = self.boto3_resource()

        wanted = frozenset(policy.boto3_resource().arn for policy in policies)
        existing = frozenset(policy.arn for policy in res.attached_policies.all())

        to_detach = existing - wanted
        to_attach = wanted - existing

        for policy_arn in to_detach:
            res.detach_policy(PolicyArn=policy_arn)

        for policy_arn in to_attach:
            res.attach_policy(PolicyArn=policy_arn)
