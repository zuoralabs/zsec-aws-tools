import boto3
import abc
import json
from typing import Tuple, Dict, Optional, Mapping, Callable, Generator
from functools import partial
from .cleaning import clean_up_stack
import logging
import time
import uuid
from types import MappingProxyType
from toolz import pipe
from .meta import get_operation_model, type_name_mapping
from .async_tools import map_async

logger = logging.getLogger(__name__)

ACCOUNT_ID_ARN_INDEX = 4
REGION_ID_ARN_INDEX = 3

zsec_tools_manager_tag_value = 'zsec_aws_tools'
manager_tag_key = 'Manager'


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


# noinspection PyPep8Naming
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
    sdk_name: str  # name in sdk functions, for example create_*, delete_*, etc.
    _sdk_name_plural_form_override: str = None
    name_key: str = 'Name'
    session: boto3.Session
    region_name: str
    service_name: str
    has_arn: bool
    index_id_key: str  # the key that is given to `describe()` or `get()` to obtain description.
    not_found_exception_name: str
    non_creation_parameters = ()

    index_id: Optional[str]

    def __init__(self, session, region_name=None, name=None, index_id=None,
                 ztid: Optional[uuid.UUID] = None,
                 old_names=(),
                 config: Optional[Mapping] = None,
                 assume_exists: bool = False,
                 manager: str = zsec_tools_manager_tag_value):
        """
        WARNING: if given, name is assumed to identify the condition set, although this is not always true

        config contains the same kwargs as the create function for this resource.
        """
        self.session = session
        self.region_name = region_name
        self.service_client = session.client(self.service_name, region_name=region_name)
        self.ztid = ztid
        self.manager = manager

        self.old_versions = [
            self.__class__(session=session, region_name=region_name, name=old_name)
            for old_name in old_names]

        clean_up_stack.append(self.clean_old_versions)

        if not (name or index_id):
            raise ValueError("Invalid input. Must supply `name` or `index_id`.")

        if self.index_id_key == self.name_key:
            self.name = self.index_id = name or index_id
            self.exists = assume_exists or self._detect_existence_using_index_id()
        elif index_id:
            self.index_id = index_id
            self.exists = assume_exists or self._detect_existence_using_index_id()
            if self.exists:
                self.name = self.describe()[self.name_key]
            if name:
                assert self.name == name
        else:
            assert name
            self.name = name
            maybe_index_value = self._get_index_id_from_ztid() if ztid else None
            if maybe_index_value is None:
                maybe_index_value = self._get_index_id_from_name()

            if maybe_index_value:
                self.index_id = maybe_index_value
                self.exists = True
            else:
                self.index_id = None
                self.exists = False
                if assume_exists:
                    raise ValueError("{} assumed to exist, but it does not exist.".format(self))

        self.config = MappingProxyType(config or {})

    @property
    def manager(self) -> str:
        return self._manager

    @manager.setter
    def manager(self, value: str):
        self._manager = value
        # flush cache for processed_config when config is set.
        self._processed_config = None

    @property
    def config(self) -> Mapping:
        return self._config

    @config.setter
    def config(self, config: Mapping) -> None:
        self._config = config
        # flush cache for processed_config when config is set.
        self._processed_config = None

    @classmethod
    def sdk_name_plural_form(cls) -> str:
        return cls._sdk_name_plural_form_override or (
            cls.sdk_name[:-1] + 'ies' if cls.sdk_name[-1] == 'y' and cls.sdk_name[-2] not in 'aeou'
            else cls.sdk_name + 's'
        )

    @property
    def processed_config(self) -> Mapping:
        if self._processed_config is None:
            self._processed_config = self._process_config(self.config)
        return self._processed_config

    def _detect_existence_using_index_id(self) -> bool:
        """Returns whether the resource exists.

        Requires `self.index_id` to be set, but not necessarily self.name.
        """
        try:
            self.describe()
        except getattr(self.service_client.exceptions, self.not_found_exception_name):
            return False
        else:
            return True

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.index_id == other.index_id

    def create(self, wait: bool = True, **kwargs) -> Tuple[Dict, Optional[str]]:
        """Create the resource and return the response and index_id"""
        combined_kwargs = {self.name_key: self.name}
        combined_kwargs.update(self.processed_config)
        combined_kwargs.update(kwargs)
        for key in self.non_creation_parameters:
            combined_kwargs.pop(key, None)
        client_method = getattr(self.service_client, "create_{}".format(self.sdk_name))
        resp = client_method(**combined_kwargs)
        # may or may not need to get self.top_key
        description = resp.get(self.top_key, resp)
        index_id = description.get(self.index_id_key)
        if index_id is None:
            for key, value in description.items():
                if self.index_id_key.endswith(key) or key.endswith(self.index_id_key):
                    index_id = value
                    break
        if wait:
            self.wait_until_exists()
        self.exists = True
        return resp, index_id

    def delete(self, not_exists_ok: bool = False, **kwargs) -> Optional[Dict]:
        combined_kwargs = {self.index_id_key: self.index_id}
        combined_kwargs.update(kwargs)
        client_method = getattr(self.service_client, "delete_{}".format(self.sdk_name))
        try:
            result = client_method(**combined_kwargs)
        except getattr(self.service_client.exceptions, self.not_found_exception_name):
            if not not_exists_ok:
                raise
            else:
                result = None
        self.exists = False
        return result

    def wait_until_not_exists(self) -> None:
        while self._detect_existence_using_index_id():
            logger.info("Waiting until {} not exists ...".format(self))
            time.sleep(1)

    def wait_until_exists(self) -> None:
        while not self._detect_existence_using_index_id():
            logger.info("Waiting until {} exists ...".format(self))
            time.sleep(1)

    def clean_old_versions(self):
        for old_version in self.old_versions:
            old_version.delete()

    def _get_index_id_from_ztid(self) -> Optional[str]:
        """Return ID using self.name

        Requires that self.ztid is set and that it is unique.
        Should only be called during `__init__` to set `self.index_id`.
        If it returns a string, it means this resource exists.

        """
        for res in self.list_with_tags(self.session, self.region_name):  # type: AWSResource
            if res.ztid == self.ztid:
                return res.name

    @classmethod
    @abc.abstractmethod
    def list_with_tags(cls, session, region_name=None, sync=False) -> Generator['AWSResource', None, None]:
        pass

    @abc.abstractmethod
    def _get_index_id_from_name(self) -> Optional[str]:
        """Return ID using self.name

        Requires that self.name is set and that it is unique.
        Should only be called during `__init__` to set `self.index_id`.
        If it returns a string, it means this resource exists.

        """
        pass

    @abc.abstractmethod
    def describe(self) -> Dict:
        """
        Must not depend on self.config.
        :return: description
        """
        pass

    def _process_config(self, config: Mapping) -> Mapping:
        processed_config = dict(config)
        processed_config[self.name_key] = self.name

        for kk, vv in processed_config.items():
            if kk not in self.non_creation_parameters:
                operation_model = get_operation_model(self.service_client, 'create_{}'.format(self.sdk_name))
                shape = operation_model.input_shape.members[kk]
                _aws_input_type = type_name_mapping[shape.type_name]
                while not isinstance(vv, _aws_input_type):
                    if isinstance(vv, Callable):
                        vv = vv(self)
                    elif isinstance(vv, Mapping) and type(vv) is not dict:
                        vv = dict(vv)
                    elif isinstance(vv, (dict, list, int)) and _aws_input_type is str:
                        vv = json.dumps(vv)
                    elif isinstance(vv, str) and _aws_input_type is bytes:
                        vv = vv.encode()
                    else:
                        vv = _aws_input_type(vv)

                processed_config[kk] = vv

        return MappingProxyType(processed_config)

    @abc.abstractmethod
    def put(self, wait: bool = True, force: bool = False):
        """Create or update resource according to config. Idempotent.

        :param wait: whether to wait on resource creation. Only applicable if resource is awaitable.
        :param force: whether to force update even if the resource fails manager checks. Not always implemented.
        :return:
        """
        pass


class AwaitableAWSResource(AWSResource, abc.ABC):
    existence_waiter_name: str
    index_id_key: str
    index_id: str

    def wait(self, waiter_name: str, **kwargs):
        """
        :param waiter_name: which waiter name to use
        :param kwargs: see one of the following for kwargs:
            iam: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#waiters
            lambda: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/lambda.html#waiters
        """
        waiter = self.service_client.get_waiter(waiter_name)
        combined_kwargs = {self.index_id_key: self.index_id}
        combined_kwargs.update(kwargs)
        waiter.wait(**combined_kwargs)

    def wait_until_exists(self):
        self.wait(self.existence_waiter_name)


class HasServiceResource(AWSResource, abc.ABC):
    def boto3_resource(self):
        cls = getattr(self.session.resource(self.service_name), self.top_key)
        return cls(self.index_id)

    @staticmethod
    @abc.abstractmethod
    def _get_index_id_and_tags_from_boto3_resource(boto3_resource) -> Tuple[str, Optional[Dict]]:
        pass

    @classmethod
    def _tagged_resource(cls, boto_res, session, region_name) -> Optional['AWSResource']:
        index_id, tags = cls._get_index_id_and_tags_from_boto3_resource(boto_res)
        if tags:
            return cls(session=session,
                       region_name=region_name,
                       index_id=index_id,
                       ztid=pipe(tags.get('ztid'), lambda x: uuid.UUID(x) if x else None),
                       config={'Tags': tags},
                       assume_exists=True)

    @classmethod
    def list_with_tags(cls, session, region_name=None, sync=False) -> Generator['AWSResource', None, None]:
        service_resource = session.resource(cls.service_name, region_name=region_name)

        # scroll(getattr(self.service_client, list_{}, Scope='Local')
        collection = getattr(service_resource, cls.sdk_name_plural_form()).all()

        yield from filter(None, map_async(partial(cls._tagged_resource, session=session, region_name=region_name),
                                          collection, sync=sync))


def standard_tags(res: AWSResource) -> Mapping:
    """Provide Manager and ztid tags"""
    return {manager_tag_key: res.manager,
            'ztid': str(res.ztid or uuid.uuid4())}
