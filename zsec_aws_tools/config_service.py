import logging
import uuid
from typing import Dict, Mapping, Tuple, Optional, Generator
from types import MappingProxyType

from toolz import pipe, merge, first, partial
from toolz.curried import assoc

import boto3

from .meta import apply_with_relevant_kwargs, get_operation_model
from .basic import AWSResource, standard_tags, scroll
from .async_tools import map_async

logger = logging.getLogger(__name__)


class ConfigRule(AWSResource):

    top_key = 'ConfigRule'
    index_id_key = 'ConfigRuleName'
    name_key = 'ConfigRuleName'
    service_name = 'config'
    sdk_name = 'config_rule'
    not_found_exception_name = 'NoSuchConfigRuleException'
    non_creation_parameters = ['Tags']

    def _process_config(self, config: Mapping) -> Mapping:
        tags = [{'Key': k, 'Value': v} for k, v in merge(standard_tags(self), config.get('Tags', {})).items()]

        processed_config: Dict = dict(config)
        processed_config['ConfigRule'][self.name_key] = self.name
        # original tags takes precedence if there is a conflict
        processed_config['Tags'] = tags

        for kk, vv in processed_config.items():
            if kk not in self.non_creation_parameters:
                operation_model = get_operation_model(self.service_client, 'put_{}'.format(self.sdk_name))
                shape = operation_model.input_shape.members[kk]
                processed_config[kk] = self._process_config_value(shape, vv)

        return MappingProxyType(processed_config)

    def _get_index_id_from_name(self) -> Optional[str]:
        raise ValueError('Should not be called')

    @classmethod
    def _tagged_resource(cls, description, session: boto3.Session, region_name: str, service_client) \
            -> Optional['AWSResource']:
        arn = description['ConfigRuleArn']
        tags = {item['Key']: item['Value'] for item in
                scroll(service_client.list_tags_for_resource, ResourceArn=arn, resp_key='Tags')}
        index_id = description[cls.index_id_key]

        if tags:
            return cls(session=session,
                       region_name=region_name,
                       index_id=index_id,
                       ztid=pipe(tags.get('ztid'), lambda x: uuid.UUID(x) if x else None),
                       config={'Tags': tags},
                       assume_exists=True)

    @classmethod
    def list_with_tags(cls, session, region_name=None, sync=False) -> Generator['AWSResource', None, None]:
        service_client = session.client('cls.service_name')
        collection = scroll(service_client.describe_config_rules, resp_key='ConfigRules')
        yield from filter(None, map_async(partial(cls._tagged_resource, session=session, region_name=region_name),
                                          collection, sync=sync))

    def describe(self, **kwargs) -> Dict:
        return first(scroll(self.service_client.describe_config_rules,
                            ConfigRuleNames=[self.index_id],
                            resp_key='ConfigRules'))

    @property
    def arn(self) -> str:
        return self.describe()['ConfigRuleArn']

    def put(self, wait: bool = True, force: bool = False):
        kwargs = {self.index_id_key: self.index_id, **self.processed_config}
        # put_config_rule takes Tags args; no need to set tags separately
        if self.exists:
            apply_with_relevant_kwargs(self.service_client, self.service_client.put_config_rule, kwargs)
        else:
            logger.info(f'creating f{self.sdk_name}')
            assert self.index_id
            apply_with_relevant_kwargs(self.service_client, self.service_client.put_config_rule, kwargs)
            logger.info(f'finished creating {self.sdk_name}')
            if wait:
                self.wait_until_exists()
                self.exists = True
