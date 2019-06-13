"""
Make sure you have a profile named 'test-fms' that you have set up as the FMS delegate. 
"""

import enum
import boto3
import zsec_aws_tools.waf as zwaf
from zsec_aws_tools.waf import RuleElement
from zsec_aws_tools import scroll
import toolz

region_name = 'us-east-1'
session = boto3.Session(profile_name='test-waf', region_name=region_name)

# DANGEROUS! Remove test creation policies at your own risk!
DO_TEST_CREATE_POLICY = False

# create rule in each supported region
ip_set = zwaf.IPSet(session, region_name, name='FMSIPset')
ip_set.update(insertions=[{'Type': 'IPV4', 'Value': '1.1.1.1/32'}])

ip_set_2 = zwaf.IPSet(session, region_name, name='FMSIPset')
ip_set_2.update(insertions=[{'Type': 'IPV4', 'Value': '2.1.1.1/32'}])

ip_blacklist_rule = zwaf.Rule(session, region_name, name='FMSIPBlacklistRule')
test_rule = zwaf.Rule(session, region_name, name='testrule')


def test_update_rule():
    ip_blacklist_rule.update(insertions=[RuleElement(ip_set), -RuleElement(ip_set_2)])
    condition_sets = list(ip_blacklist_rule)
    assert RuleElement(ip_set) in condition_sets
    assert - RuleElement(ip_set_2) in condition_sets
    ip_blacklist_rule.update(deletions=[-RuleElement(ip_set_2)])
    assert -RuleElement(ip_set_2) not in ip_blacklist_rule


def test_put_rule():
    ip_blacklist_rule.put([RuleElement(ip_set), -RuleElement(ip_set_2)])
    condition_sets = list(ip_blacklist_rule)
    assert RuleElement(ip_set) in condition_sets
    assert -RuleElement(ip_set_2) in condition_sets
    ip_blacklist_rule.put([RuleElement(ip_set)])
    assert -RuleElement(ip_set_2) not in ip_blacklist_rule


# create rule group in each supported region


def test_put_rule_group():
    rule_group = zwaf.RuleGroup(session, region_name, name='testrulegroup')

    rule_group_element_1 = {
            'Priority': 2,
            'RuleId': test_rule.id_,
            'Action': {'Type': 'BLOCK'},
            #'OverrideAction': {'Type': 'NONE'},
            'Type': 'REGULAR',
            #'ExcludedRules': []
            }

    rule_group_element_2 = {
            'Priority': 3,
            'RuleId': ip_blacklist_rule.id_,
            'Action': {'Type': 'BLOCK'},
            #'OverrideAction': {'Type': 'NONE'},
            'Type': 'REGULAR',
            #'ExcludedRules': []
            }

    rule_group.put([rule_group_element_1, rule_group_element_2])
    rules = list(rule_group.rules())
    assert test_rule in rules
    assert ip_blacklist_rule in rules
    rule_group.put([rule_group_element_2])
    assert test_rule not in rule_group.rules()


def test_create_policy():
    if DO_TEST_CREATE_POLICY:
        rule_group = zwaf.RuleGroup(session, region_name, name='testrulegroup')

        test_policy = zwaf.Policy(session, name='test_policy', ensure_exists=False)
        test_policy.put(
                resource_tags=[],
                managed_service_data = {
                    'type': 'WAF',
                    'ruleGroups': [{'id': rule_group.id_,
                        'overrideAction': {'type': 'COUNT'}}],
                    'defaultAction': {'type': 'BLOCK'}},
                )

