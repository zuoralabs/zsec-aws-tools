import boto3
import abc
from typing import Tuple, Dict, Optional, Iterable
from .cleaning import clean_up_stack
import logging
from toolz import first
import time


logger = logging.getLogger(__name__)

ACCOUNT_ID_ARN_INDEX = 4
REGION_ID_ARN_INDEX = 3


def get_account_id(session: boto3.Session, context=None) -> str:
    """Returns AWS account ID

    :param session: AWS session
    :param context: lambda handler context -- optional
    :return: account ID
    """

    sts = session.client('sts')

    if not context:
        # See https://stackoverflow.com/questions/36709461/get-aws-account-id-from-boto
        return sts.get_caller_identity()['Account']
    else:
        # see aws-scripting-guy's gist https://gist.github.com/aws-scripting-guy/83d901527fa7adc271da
        arn = context.invoked_function_arn
        return arn.split(':')[ACCOUNT_ID_ARN_INDEX]


resp_key_mapping = {('WAFRegional', 'list_web_acls'): 'WebACLs',
                    ('WAF', 'list_web_acls'): 'WebACLs',
                    'list_rule_groups': 'RuleGroups',
                    'list_activated_rules_in_rule_group': 'ActivatedRules',
                    'list_rules': 'Rules',
                    'list_ip_sets': 'IPSets',
                    'list_regex_match_sets': 'RegexMatchSets',
                    'list_regex_pattern_sets': 'RegexPatternSets',
                    'list_byte_match_sets': 'ByteMatchSets',
                    'list_geo_match_sets': 'GeoMatchSets',
                    ('IAM', 'list_policies'): 'Policies',
                    ('IAM', 'list_role_policies'): 'PolicyNames',
                    ('FMS', 'list_policies'): 'PolicyList',

                    'get_rest_apis': 'items',
                    'describe_load_balancers': 'LoadBalancers',
                    'list_accounts': 'Accounts',

                    ('Lambda', 'list_functions'): 'Functions',
                    }

req_marker_key_mapping = {
    'list_web_acls': 'NextMarker',
    'list_ip_sets': 'NextMarker',
    'list_activated_rules_in_rule_group': 'NextMarker',
    'get_rest_apis': 'position',
    'list_accounts': 'NextToken',
    'describe_load_balancers': 'Marker',
    'list_functions': 'Marker',
}

resp_marker_key_mapping = req_marker_key_mapping.copy()
resp_marker_key_mapping['list_functions'] = 'NextMarker'

possible_markers = frozenset(resp_marker_key_mapping.values())


def _get_key(key_mapping, fn):
    maybe_key = key_mapping.get(fn.__name__)
    if maybe_key:
        return maybe_key
    else:
        return key_mapping.get((fn.__self__.__class__.__name__, fn.__name__), None)


def scroll(fn, resp_key=None, resp_marker_key=None, req_marker_key=None, **kwargs):
    """
    :return: Iterable over items
    """

    resp = fn(**kwargs)

    if not resp_key:
        _maybe_key = _get_key(resp_key_mapping, fn)

        if _maybe_key:
            resp_key = _maybe_key
        else:
            _possible_keys = set(resp.keys()) - {'ResponseMetadata'} - possible_markers
            assert len(_possible_keys) == 1
            resp_key = _possible_keys.pop()
            print('By elimination, using resp_key={} in call to {}'.format(resp_key, fn.__name__))

    yield from resp[resp_key]

    if not resp_marker_key:
        _maybe_key = _get_key(resp_marker_key_mapping, fn)
        if _maybe_key:
            resp_marker_key = _maybe_key
        else:
            _possible_keys = {kk for kk in resp.keys() if kk.endswith('Marker') or kk.startswith('Next')}
            if _possible_keys:
                resp_marker_key = _possible_keys.pop()
                print('Guess marker_key={} in call to {}'.format(resp_marker_key, fn.__name__))
            else:
                print("Could not guess marker_key in call to {}. Maybe no marker? Keys: ".format(fn.__name__,
                                                                                                 resp.keys()))
                return

    if not req_marker_key:
        _maybe_key = _get_key(req_marker_key_mapping, fn)
        if _maybe_key:
            req_marker_key = _maybe_key
        else:
            req_marker_key = resp_marker_key

    NextMarker = resp.get(resp_marker_key)

    while NextMarker:
        next_args = {req_marker_key: NextMarker}
        next_args.update(kwargs)
        resp = fn(**next_args)
        yield from resp[resp_key]
        NextMarker = resp.get(resp_marker_key)


class AWSResource(abc.ABC):
    top_key: str
    id_key: str
    sdk_name: str     # name in sdk functions, for example create_*, delete_*, etc.
    name_key: str = 'Name'
    session: boto3.Session
    region_name: str
    client_name: str
    has_arn: bool
    has_id: bool
    index_id_key: str    # the key that is given to describe or get to obtain description.
    not_found_exception_name: str
    non_creation_parameters = ()

    def __init__(self, session, region_name=None, name=None, index_id=None, old_names=(),
                 config: Optional[Dict] = None):
        """
        WARNING: if given, name is assumed to identify the condition set, although this is not always true

        config contains the same kwargs as the create function for this resource.
        """
        self.session = session
        self.region_name = region_name
        self.service_client = session.client(self.client_name, region_name=region_name)

        self.old_versions = [
            self.__class__(session=session, region_name=region_name, name=old_name)
            for old_name in old_names]

        clean_up_stack.append(self.clean_old_versions)

        assert name or index_id

        if self.index_id_key == self.name_key:
            self.name = self.index_id = name or index_id
            try:
                self.describe()
            except getattr(self.service_client.exceptions, self.not_found_exception_name):
                self.exists = False
            else:
                self.exists = True
        elif name:
            self.name = name
            maybe_index_value = self._get_index_id_from_name()
            if maybe_index_value:
                self.index_id = maybe_index_value
                self.exists = True
            else:
                self.index_id = ''
                self.exists = False
        elif index_id:
            self.index_id = index_id
            self.name = self.describe()[self.name_key]
            self.exists = True

        self.config = config or {}
        self._process_config()

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.index_id == other.index_id

    def create(self, **kwargs) -> str:
        combined_kwargs = {self.name_key: self.name}
        combined_kwargs.update(self.config)
        combined_kwargs.update(kwargs)
        for key in self.non_creation_parameters:
            combined_kwargs.pop(key, None)
        client_method = getattr(self.service_client, "create_{}".format(self.sdk_name))
        resp = client_method(**combined_kwargs)
        # may or may not need to get self.top_key
        result = resp.get(self.top_key, resp)[self.index_id_key]
        self.exists = True
        return result

    def delete(self, **kwargs):
        combined_kwargs = {self.name_key: self.name}
        combined_kwargs.update(kwargs)
        client_method = getattr(self.service_client, "delete_{}".format(self.sdk_name))
        result = client_method(**combined_kwargs)
        self.exists = False
        return result

    def await_deletion(self):
        while True:
            try:
                self.describe()
            except getattr(self.service_client.exceptions, self.not_found_exception_name):
                return
            else:
                logger.info("Waiting to confirm deletion ...")
                time.sleep(1)

    def clean_old_versions(self):
        for old_version in self.old_versions:
            old_version.delete()

    @abc.abstractmethod
    def _get_index_id_from_name(self) -> Optional[str]:
        """Return ID using self.name

        Requires that self.name is set and that it is unique.
        Should only be called during `__init__` to set `self.id_`.

        """
        pass

    @abc.abstractmethod
    def describe(self) -> Dict:
        """
        Must not depend on self.config.
        :return: description
        """
        pass

    def _process_config(self) -> None:
        self.config[self.name_key] = self.name


class AwaitableAWSResource(AWSResource, abc.ABC):
    waiter_name: str
    index_id_key: str
    index_id: str

    def wait(self, **kwargs):
        """
        :param kwargs: see one of the following for kwargs:
            iam: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#waiters
            lambda: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/lambda.html#waiters
        """
        waiter = self.service_client.get_waiter(self.waiter_name)
        combined_kwargs = {self.index_id_key: self.index_id}
        combined_kwargs.update(kwargs)
        waiter.wait(**combined_kwargs)

    def create(self, wait: bool = True, **kwargs) -> str:
        result = super().create(**kwargs)
        if wait:
            self.wait()
        return result


def get_index_id_from_description(self: AWSResource) -> Optional[str]:
    try:
        return self.describe()[self.id_key]
    except self.service_client.exceptions.ResourceNotFoundException:
        return None
    #except self.service_client.exceptions.NoSuchEntityException:
    #    return None
