import boto3
from typing import Tuple

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


resp_key_mapping = {'list_web_acls': 'WebACLs',
                    'list_rule_groups': 'RuleGroups',
                    'list_activated_rules_in_rule_group': 'ActivatedRules',
                    'list_rules': 'Rules',
                    'list_ip_sets': 'IPSets',
                    'list_regex_match_sets': 'RegexMatchSets',
                    'list_regex_pattern_sets': 'RegexPatternSets',
                    'list_byte_match_sets': 'ByteMatchSets',
                    'list_geo_match_sets': 'GeoMatchSets',
                    'list_policies': 'PolicyList',

                    'get_rest_apis': 'items',
                    'describe_load_balancers': 'LoadBalancers',
                    'list_accounts': 'Accounts',
                    }

marker_key_mapping = {
    'list_web_acls': 'NextMarker',
    'list_ip_sets': 'NextMarker',
    'list_activated_rules_in_rule_group': 'NextMarker',
    'get_rest_apis': 'position',
    'list_accounts': 'NextToken',
    'describe_load_balancers': 'Marker',
}

possible_markers = frozenset(marker_key_mapping.values())


def scroll(fn, resp_key=None, marker_key=None, **kwargs):
    """
    :return: Iterable over items
    """

    resp = fn(**kwargs)

    if not resp_key:
        _maybe_key = resp_key_mapping.get(fn.__name__)
        if _maybe_key:
            resp_key = _maybe_key
        else:
            _possible_keys = set(resp.keys()) - {'ResponseMetadata'} - possible_markers
            assert len(_possible_keys) == 1
            resp_key = _possible_keys.pop()
            print('By elimination, using resp_key={} in call to {}'.format(resp_key, fn.__name__))

    yield from resp[resp_key]

    if not marker_key:
        _maybe_key = marker_key_mapping.get(fn.__name__)
        if _maybe_key:
            marker_key = _maybe_key
        else:
            _possible_keys = {kk for kk in resp.keys() if kk.endswith('Marker') or kk.startswith('Next')}
            if _possible_keys:
                marker_key = _possible_keys.pop()
                print('Guess marker_key={} in call to {}'.format(marker_key, fn.__name__))
            else:
                print("Could not guess marker_key in call to {}. Maybe no marker? Keys: ".format(fn.__name__, resp.keys()))
                return

    NextMarker = resp.get(marker_key)

    while NextMarker:
        next_args = {marker_key: NextMarker}
        next_args.update(kwargs)
        resp = fn(**next_args)
        yield from resp[resp_key]
        NextMarker = resp.get(marker_key)
