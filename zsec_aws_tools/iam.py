import json
import logging
import boto3
from typing import Dict, Iterable, Tuple, Optional
from .basic import AWSResource, scroll, AwaitableAWSResource, add_ztid_tags, add_manager_tags, manager_tag_key
from toolz import first
import abc
from .meta import apply_with_relevant_kwargs


logger = logging.getLogger(__name__)

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

    def _process_config(self):
        add_manager_tags(self)
        add_ztid_tags(self)

        # Hack to convert to IAM type tag argument conventions. Should change `add_manager_tags` and
        # `add_ztid_tags` instead.
        self.config['Tags'] = [{'Key': k, 'Value': v} for k, v in self.config['Tags'].items()]

        super()._process_config()

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
            remote_tags = {tag['Key']: tag['Value'] for tag in remote_description['Tags']}

            tags = {tag['Key']: tag['Value'] for tag in self.config['Tags']}

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
    top_key: str = 'Policy'
    id_key: str = 'PolicyId'
    name_key: str = 'PolicyName'
    sdk_name: str = 'policy'
    index_id_key = 'PolicyArn'
    existence_waiter_name = 'policy_exists'

    def _get_index_id_from_name(self):
        return self._get_description_from_name()['Arn']

    def _get_description_from_name(self):
        policies = scroll(self.service_client.list_policies)
        try:
            return first(filter(lambda x: x['PolicyName'] == self.name, policies))
        except StopIteration:
            return None

    def update(self):
        raise NotImplementedError


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

    def _process_config(self):
        super()._process_config()
        policy_document = self.config.get('AssumeRolePolicyDocument')
        if policy_document is not None:
            self.config['AssumeRolePolicyDocument'] = json.dumps(policy_document)

    def create(self, wait: bool = True, **kwargs) -> Tuple[Dict, Optional[str]]:
        result = super().create(wait=wait, **kwargs)
        if 'Policies' in self.config:
            self.put_policies(self.config['Policies'])
        return result

    def update(self):
        update_kwargs = self.config.copy()
        update_kwargs['PolicyDocument'] = update_kwargs['AssumeRolePolicyDocument']
        apply_with_relevant_kwargs(self.service_client, self.service_client.update_role,
                                   self.config, ignore_when_missing_required_keys=True)

        apply_with_relevant_kwargs(self.service_client, self.service_client.update_assume_role_policy,
                                   self.config, ignore_when_missing_required_keys=True)

        apply_with_relevant_kwargs(self.service_client, self.service_client.tag_role,
                                   self.config, ignore_when_missing_required_keys=True)

        apply_with_relevant_kwargs(self.service_client, self.service_client.put_role_permissions_boundary,
                                   self.config, ignore_when_missing_required_keys=True)

        self.put_policies(self.config['Policies'])

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
