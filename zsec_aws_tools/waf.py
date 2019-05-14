"""
A resource API for WAF and WAF-regional
"""

from enum import Enum, auto
from typing import Iterable, Dict, Container, Union, Generator, Optional, List
import boto3
from .basic import scroll
import abc
import logging
import json
import collections

logger = logging.getLogger(__name__)


class Kind(Enum):
    policy = 'policy'

    # generated via
    # for xx in [x[7:] for x in dir(waf_regional) if x.startswith('update')]:
    #     print('{} = \'{}\''.format(xx, xx))

    byte_match_set = 'byte_match_set'
    geo_match_set = 'geo_match_set'
    ip_set = 'ip_set'
    rate_based_rule = 'rate_based_rule'
    regex_match_set = 'regex_match_set'
    regex_pattern_set = 'regex_pattern_set'
    rule = 'rule'
    rule_group = 'rule_group'
    size_constraint_set = 'size_constraint_set'
    sql_injection_match_set = 'sql_injection_match_set'
    web_acl = 'web_acl'
    xss_match_set = 'xss_match_set'



match_type_to_kind = {'IPMatch': Kind.ip_set,
                      'ByteMatch': Kind.byte_match_set,
                      'SqlInjectionMatch': Kind.sql_injection_match_set,
                      'GeoMatch': Kind.geo_match_set,
                      'SizeConstraint': Kind.size_constraint_set,
                      'XssMatch': Kind.xss_match_set,
                      'RegexMatch': Kind.regex_match_set,
                      }


kind_to_match_type = {v: k for k, v in match_type_to_kind.items()}


def list_resources(client, kind: Kind) -> Iterable[Dict]:
    if kind == Kind.policy:
        return scroll(client.list_policies, MaxResults=100)
    else:
        fn = getattr(client, 'list_{}s'.format(kind.value))
        return scroll(fn)


def create_resource(client, change_token, kind: Kind, name, **kwargs):
    fn = getattr(client, 'create_{}'.format(kind.value))

    metric_name = name.replace('-', '').replace('_', '')

    if kind in [Kind.rule, Kind.rule_group]:
        return fn(Name=name, MetricName=metric_name, ChangeToken=change_token)
    elif kind in [Kind.rate_based_rule]:
        _kwargs = dict(RateKey='IP', RateLimit=2000)
        _kwargs.update(kwargs)
        return fn(Name=name, MetricName=metric_name, ChangeToken=change_token, **_kwargs)
    elif kind == Kind.web_acl:
        _kwargs = dict(DefaultAction={'Type': 'ALLOW'})
        return fn(Name=name, MetricName=metric_name, ChangeToken=change_token, **_kwargs)
    else:
        return fn(Name=name, ChangeToken=change_token)


def get_service_name(kind: Kind, region_name):
    if kind in {Kind.policy}:
        return 'fms'
    elif region_name == 'global':
        return 'waf'
    else:
        return 'waf-regional'


class WAFResource(abc.ABC):
    top_key: str
    id_key: str
    kind: Kind
    name_key: str = 'Name'
    session: boto3.Session
    region_name: str

    def __init__(self, session, region_name=None, name=None, id_=None, ensure_exists=True, old_names=(),
                 creation_kwargs={}):
        """
        service_client could be waf, waf-regional, or fms

        WARNING: if given, name is assumed to identify the condition set, although this is not always true

        Caveat: do not use ensure_exists with FMS policy.
        """
        self.session = session
        self.region_name = region_name
        self.service_client = session.client(get_service_name(self.kind, region_name),
                                             region_name=region_name if region_name != 'global' else 'us-east-1')

        self.old_versions = [
            self.__class__(session, region_name=region_name, name=old_name, ensure_exists=False)
            for old_name in old_names]

        clean_up_stack.append(self.clean_old_versions)

        assert name or id_

        if name:
            self.name = name
            maybe_id = self.get_id(name)
            if maybe_id:
                self.id_ = maybe_id
                self.exists = True
            elif ensure_exists:
                if self.kind == Kind.policy:
                    raise NotImplementedError
                logger.info('{} "{}" does not exist. Creating.'.format(self.top_key, name))

                while True:
                    try:
                        resp = create_resource(self.service_client,
                                               change_token=self.service_client.get_change_token()['ChangeToken'],
                                               kind=self.kind, name = self.name, **creation_kwargs)
                        break
                    except self.service_client.exceptions.WAFStaleDataException:
                        logger.info("Got WAFStaleDataException; retrying ...")
                        continue

                self.id_ = resp[self.top_key][self.id_key]
                self.exists = True
            else:
                self.exists = False
        elif id_:
            self.id_ = id_
            self.name = self.describe()[self.name_key]
            self.exists = True

    def get_id(self, name):
        # name is assumed to be unique
        # find ID
        for item in list_resources(self.service_client, self.kind):
            if item[self.name_key] == name:
                return item[self.id_key]
        else:
            return None

    def describe(self):
        fn = getattr(self.service_client, 'get_{}'.format(self.kind.value))
        return fn(**{self.id_key: self.id_})[self.top_key]

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.id_ == other.id_

    @abc.abstractmethod
    def delete(self, **kwargs):
        pass

    def clean_old_versions(self):
        for old_version in self.old_versions:
            old_version.delete()


class UpdateableWAFResource(WAFResource, Iterable, metaclass=abc.ABCMeta):
    descriptor_key: str
    descriptors_key: str

    @abc.abstractmethod
    def __iter__(self):
        pass

    def update(self, insertions=(), deletions=(), **kwargs):
        # descriptor structure for Kind.ip:
        # {
        #   "Type": "IPV4"|"IPV6",
        #   "Value": "string"
        # }

        updates = (
                [{'Action': 'DELETE',
                  self.descriptor_key: dd}
                 for dd in deletions]
                + [{'Action': 'INSERT',
                    self.descriptor_key: dd}
                   for dd in insertions]
        )

        specific_update_fn_kwargs = {
            self.id_key: self.id_,
            'Updates': updates}

        specific_update_fn_kwargs.update(kwargs)

        specific_update_fn = getattr(self.service_client, 'update_' + self.kind.value)
        while True:
            try:
                return specific_update_fn(ChangeToken=self.service_client.get_change_token()['ChangeToken'],
                                          **specific_update_fn_kwargs)
            except self.service_client.exceptions.WAFStaleDataException:
                logger.info("Got WAFStaleDataException; retrying ...")
                continue

    def put(self, descriptors, **kwargs):
        """Idempotent -- make the live descriptors the same as the descriptors argument

        :param descriptors: the `update` method may have more help on descriptor structure
        :param kwargs: passes kwargs through to update
        :return: None
        """
        extants = list(self)

        insertions = [descriptor
                      for descriptor in descriptors
                      if descriptor not in extants
                      ]

        deletions = [descriptor
                     for descriptor in extants
                     if descriptor not in descriptors
                     ]

        if insertions or deletions:
            self.update(insertions, deletions, **kwargs)

    def delete(self):
        if self.exists:
            self.put(())
            delete_method = getattr(self.service_client, 'delete_{}'.format(self.kind.value))

            while True:
                try:
                    delete_method(ChangeToken=self.service_client.get_change_token()['ChangeToken'],
                                  **{self.id_key: self.id_})
                    break
                except self.service_client.exceptions.WAFStaleDataException:
                    logger.info("Got WAFStaleDataException; retrying ...")
                    continue

        self.exists = False


class ConditionSet(UpdateableWAFResource, Container, Iterable, metaclass=abc.ABCMeta):
    def __iter__(self):
        yield from self.descriptors()

    def __contains__(self, element):
        return element in self.descriptors()

    def descriptors(self):
        return self.describe()[self.descriptors_key]

    @property
    def base_condition_set(self):
        return self


class IPSet(ConditionSet):
    top_key = 'IPSet'
    id_key = 'IPSetId'
    descriptor_key = 'IPSetDescriptor'
    descriptors_key = 'IPSetDescriptors'
    kind = Kind.ip_set


class GeoMatchSet(ConditionSet):
    top_key = 'GeoMatchSet'
    id_key = 'GeoMatchSetId'
    descriptor_key = 'GeoMatchConstraint'
    descriptors_key = 'GeoMatchConstraints'
    kind = Kind.geo_match_set


class ByteMatchSet(ConditionSet):
    top_key = 'ByteMatchSet'
    id_key = 'ByteMatchSetId'
    descriptor_key = 'ByteMatchTuple'
    descriptors_key = 'ByteMatchTuples'
    kind = Kind.byte_match_set


class RegexMatchSet(ConditionSet):
    """

    put args:

        {
            'FieldToMatch': {
                'Type': 'URI'|'QUERY_STRING'|'HEADER'|'METHOD'|'BODY'|'SINGLE_QUERY_ARG'|'ALL_QUERY_ARGS',
                'Data': 'string'
                },
            'TextTransformation': 'NONE'|'COMPRESS_WHITE_SPACE'|'HTML_ENTITY_DECODE'|'LOWERCASE'|'CMD_LINE'|'URL_DECODE',
            'RegexPatternSetId': regex_pattern_set.id_
        }

    See waf-regional `update_regex_match_set`.

    """
    top_key = 'RegexMatchSet'
    id_key = 'RegexMatchSetId'
    descriptor_key = 'RegexMatchTuple'
    descriptors_key = 'RegexMatchTuples'
    kind = Kind.regex_match_set


class RegexPatternSet(ConditionSet):
    """
    Does not fit in a Rule, but otherwise is just like any other
    ConditionSet. Instead, put it in a RegexMatchSet.
    """
    top_key = 'RegexPatternSet'
    id_key = 'RegexPatternSetId'
    descriptor_key = 'RegexPatternString'
    descriptors_key = 'RegexPatternStrings'
    kind = Kind.regex_pattern_set

    #def __iter__(self):
    #    yield from self.describe()[self.descriptors_key]


class RuleGroup(UpdateableWAFResource):
    top_key = 'RuleGroup'
    id_key = 'RuleGroupId'
    descriptor_key = 'ActivatedRule'
    descriptors_key = 'ActivatedRules'
    kind = Kind.rule_group

    def list_activated_rules(self):
        return scroll(self.service_client.list_activated_rules_in_rule_group,
                      RuleGroupId=self.id_)

    def rules(self):
        for item in scroll(self.service_client.list_activated_rules_in_rule_group,
                           RuleGroupId=self.id_):
            yield Rule(self.session, self.region_name, id_=item[Rule.id_key])

    def __iter__(self):
        yield from self.list_activated_rules()

    def update(self, insertions=(), deletions=(), **kwargs):
        """
        Descriptor structure:

        {
            'Priority': 123,
            'RuleId': 'string',
            'Action': {
                'Type': 'BLOCK'|'ALLOW'|'COUNT'
            },
            'OverrideAction': {
                'Type': 'NONE'|'COUNT'
            },
            'Type': 'REGULAR'|'RATE_BASED'|'GROUP',
            'ExcludedRules': [
                {
                    'RuleId': 'string'
                },
            ]
        }
        """
        assert not kwargs
        super().update(insertions, deletions)


class RuleElement:
    Negated: bool
    condition_set: ConditionSet

    def __init__(self, condition_set: ConditionSet, Negated: bool = False):
        self.condition_set = condition_set
        self.Negated = Negated

    def translate_to_aws(self):
        match_type = kind_to_match_type[self.condition_set.kind]
        return {
            'Negated': self.Negated,
            'Type': match_type,
            'DataId': self.condition_set.id_,
        }

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.translate_to_aws() == other.translate_to_aws()

    def __neg__(self):
        return RuleElement(self.condition_set, Negated=not self.Negated)


class Rule(UpdateableWAFResource, Iterable):
    top_key = 'Rule'
    id_key = 'RuleId'
    kind = Kind.rule
    descriptor_key = 'Predicate'
    descriptors_key = 'Predicates'

    def __iter__(self) -> Generator[RuleElement, None, None]:
        for pred in self.describe()[self.descriptors_key]:
            _kind = match_type_to_kind[pred['Type']]
            cls = kind_to_type[_kind]
            _id = pred['DataId']
            condition_set = cls(self.session, self.region_name, id_=_id)
            yield RuleElement(condition_set, pred['Negated'])

    def update(self, insertions: Iterable[RuleElement]=(), deletions: Iterable[RuleElement]=(), **kwargs):
        _insertions = [xx.translate_to_aws() for xx in insertions]
        _deletions = [xx.translate_to_aws() for xx in deletions]
        super().update(insertions=_insertions, deletions=_deletions)


class RateBasedRule(UpdateableWAFResource, Iterable):
    """
    Note: RateBasedRule's naming conventions are odd

    After initialization, please call `put` with your RateLimit, to ensure idempotency.
    """
    top_key = 'Rule'
    id_key = 'RuleId'
    kind = Kind.rate_based_rule
    descriptor_key = 'Predicate'
    descriptors_key = 'MatchPredicates'

    def __iter__(self) -> Generator[RuleElement, None, None]:
        for pred in self.describe()[self.descriptors_key]:
            _kind = match_type_to_kind[pred['Type']]
            cls = kind_to_type[_kind]
            _id = pred['DataId']
            condition_set = cls(self.session, self.region_name, id_=_id)
            yield RuleElement(condition_set, pred['Negated'])

    def update(self, insertions: Iterable[RuleElement]=(), deletions: Iterable[RuleElement]=(), RateLimit=2000):
        _insertions = [xx.translate_to_aws() for xx in insertions]
        _deletions = [xx.translate_to_aws() for xx in deletions]
        super().update(insertions=_insertions, deletions=_deletions, RateLimit=RateLimit)


class WebACL(UpdateableWAFResource):
    top_key = 'WebACL'
    id_key = 'WebACLId'
    descriptor_key = 'ActivatedRule'
    descriptors_key = 'Rules'
    kind = Kind.web_acl

    def rules(self):
        for item in self:
            yield Rule(self.session, self.region_name, id_=item[Rule.id_key])

    def __iter__(self):
        yield from self.service_client.get_web_acl(WebACLId=self.id_)[self.top_key][self.descriptors_key]

    def update(self, insertions=(), deletions=(), **kwargs):
        """
        Descriptor structure:

        {
            'Priority': 123,
            'RuleId': 'string',
            'Action': {
                'Type': 'BLOCK'|'ALLOW'|'COUNT'
            },
            'OverrideAction': {
                'Type': 'NONE'|'COUNT'
            },
            'Type': 'REGULAR'|'RATE_BASED'|'GROUP',
            'ExcludedRules': [
                {
                    'RuleId': 'string'
                },
            ]
        }
        """
        assert not kwargs
        super().update(insertions, deletions)


class Policy(WAFResource):
    top_key = 'Policy'
    id_key = 'PolicyId'
    kind = Kind.policy
    name_key = 'PolicyName'
    fms_shield_supported_resource_types = ['AWS::ElasticLoadBalancingV2::LoadBalancer',
                                           'AWS::ElasticLoadBalancing::LoadBalancer',
                                           'AWS::EC2::EIP']

    def subtype(self):
        return self.describe()['SecurityServicePolicyData']['Type']

    def __iter__(self):
        desc = self.describe()
        policy_data = desc['SecurityServicePolicyData']
        if policy_data['Type'] == 'WAF':
            service_data = json.loads(policy_data['ManagedServiceData'])
            for rule_group in service_data['ruleGroups']:
                yield RuleGroup(self.session, self.region_name, id_=rule_group['id'])

    def put(self, managed_service_data,
            policy_type: Optional[str] = None,
            resource_tags: Optional[List[Dict]] = None,
            resource_type: Optional[str] = None,
            resource_type_list: Optional[List[str]] = None,
            include_map: Iterable = (),
            exclude_map: Iterable = ()):
        """
        resource_tags structure:
            [
                {
                    'Key': 'string',
                    'Value': 'string'
                },
            ]


        managed_service_data:
            see ManagedServiceData in fms `put_policy`

            examples:

                {
                    'type': 'WAF',
                    'ruleGroups': [{'id': rule_group.id_,
                        'overrideAction': {'type': 'COUNT'}}],
                    'defaultAction': {'type': 'BLOCK'}
                }

                { "type":"SHIELD_ADVANCED" }


        include_map:
             if empty, equivalent to listing all accounts

        """
        if policy_type is None:
            policy_type = managed_service_data['type']

        if resource_type is None:
            if policy_type == 'WAF':
                if self.region_name == 'global':
                    resource_type = 'AWS::CloudFront::Distribution'
                else:
                    resource_type = 'AWS::ElasticLoadBalancingV2::LoadBalancer'
            elif policy_type == 'SHIELD_ADVANCED':

                if self.region_name == 'global':
                    resource_type = 'AWS::CloudFront::Distribution'
                else:
                    resource_type = 'ResourceTypeList'
                    if resource_type_list is None:
                        resource_type_list = self.fms_shield_supported_resource_types

        policy = {
            #'PolicyId': 'string',
            'PolicyName': self.name,  # Required
            #'PolicyUpdateToken': 'string',
            'SecurityServicePolicyData': {
                'Type': policy_type,
                'ManagedServiceData': json.dumps(managed_service_data)
            },
            'ResourceType': resource_type,
            'ExcludeResourceTags': False,
            'RemediationEnabled': True,
            'IncludeMap': {
                'ACCOUNT': list(include_map)
            },
            'ExcludeMap': {
                'ACCOUNT': list(exclude_map)
            }
        }

        if self.exists:
            policy['PolicyId'] = self.id_
            policy['PolicyUpdateToken'] = self.describe()['PolicyUpdateToken']

        policy['ResourceTags'] = resource_tags or []

        if resource_type_list:
            policy['ResourceTypeList'] = resource_type_list

        self.service_client.put_policy(Policy=policy)

        self.exists = True

    def delete(self, DeleteAllPolicyResources: bool = False):
        resp = self.service_client.delete_policy(
            PolicyId=self.id_,
            DeleteAllPolicyResources= DeleteAllPolicyResources
        )
        self.exists = False
        return resp


kind_to_type = {
    cls.kind: cls
    for cls in [Policy, Rule, RateBasedRule, RuleGroup,
                IPSet, GeoMatchSet, ByteMatchSet, RegexMatchSet, RegexPatternSet, WebACL]
}


def copy_condition_set(descriptors: Iterable, set_b: ConditionSet):
    to_insert = list(descriptors)
    to_delete = list()

    for descriptor in set_b:
        if descriptor not in to_insert:
            to_delete.append(descriptor)

    set_b.update(insertions=to_insert, deletions=to_delete)


def copy_regex_match_set_resolving_pattern_sets_by_name(set_a: RegexMatchSet, set_b: RegexPatternSet):
    descriptors = list()
    for descriptor in set_a:
        original_pattern_set = RegexPatternSet(set_a.session, region_name=set_a.region_name,
                                               id_=descriptor['RegexPatternSetId'], ensure_exists=False)
        target_pattern_set = RegexPatternSet(set_b.session, region_name=set_b.region_name,
                                             name=original_pattern_set.name, ensure_exists=False)
        descriptor['RegexPatternSetId'] = target_pattern_set.id_
        descriptors.append(descriptor)

    copy_condition_set(descriptors, set_b)


# keep track of old versions that need cleaning
clean_up_stack = []


def clean_up():
    while clean_up_stack:
        thunk = clean_up_stack.pop()
        thunk()
