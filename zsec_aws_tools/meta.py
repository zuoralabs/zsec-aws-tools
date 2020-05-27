import functools
from typing import Tuple, Generator

import boto3
import botocore.model
import pynamodb.models
from pynamodb.attributes import UnicodeAttribute

type_name_mapping = {'string': str,
                     'long': int,
                     'blob': bytes,
                     'list': list,
                     'double': int,
                     'structure': dict,
                     'map': dict,
                     'integer': int,
                     'timestamp': str,  # not sure about this
                     }


def get_operation_model(svc, fn):
    """Return operation model for method of a service model

    :param svc: AWS service client
    :param fn: method of svc
    :return: operation model for fn
    """
    if isinstance(fn, str):
        func_name = fn
    else:
        func_name = fn.__name__
    return svc._service_model.operation_model(svc._PY_TO_OP_NAME[func_name])


def apply_with_relevant_kwargs(svc, fn, kwargs, ignore_when_missing_required_keys=False):
    operation_model = get_operation_model(svc, fn)
    desired_keys = operation_model.input_shape.members.keys()
    filtered_kwargs = {k: v for k, v in kwargs.items() if k in desired_keys}
    required_keys = operation_model.input_shape.required_members

    if ignore_when_missing_required_keys and not frozenset(kwargs.keys()).issuperset(required_keys):
        return
    else:
        return fn(**filtered_kwargs)


def get_parameter_shapes(service_client, *operation_names: str) -> Generator[Tuple[str, botocore.model.Shape], None, None]:
    for operation_name in operation_names:
        operation_model = get_operation_model(service_client, operation_name)
        for key, shape in operation_model.input_shape.members.items():
            yield key, shape


class PartialModel(pynamodb.models.Model):
    """
    Model without defined region and credentials
    """

    @classmethod
    def attach_credentials(cls, session: boto3.Session, region_name: str = None) -> __class__:
        credentials = session.get_credentials()
        ssm = session.client('ssm', region_name=region_name)
        _table_name = ssm.get_parameter(Name=cls.table_parameter_name)['Parameter']['Value']

        @functools.wraps(__class__)
        class Completed(cls):
            class Meta:
                table_name = _table_name
                region = region_name
                aws_access_key_id = credentials.access_key
                aws_secret_access_key = credentials.secret_key
                aws_session_token = credentials.token

        return Completed

    @classmethod
    def set_table_name(cls, session: boto3.Session, table_name: str, **kwargs):
        ssm = session.client('ssm')
        ssm.put_parameter(
            Name=cls.table_parameter_name,
            Description='Name of the table containing resources created by fleet former, indexed by ZRN.',
            Value=table_name,
            Type='String',
            AllowedPattern=r'[\w_-]+$',
            **kwargs
        )


class CloudResourceMetaDescriptionBase(PartialModel):
    zrn = UnicodeAttribute(hash_key=True)
    ztid = UnicodeAttribute()
    manager = UnicodeAttribute()
    region_name = UnicodeAttribute()
    type = UnicodeAttribute()
    name = UnicodeAttribute()
    account_number = UnicodeAttribute()
    index_id = UnicodeAttribute()
    table_parameter_name = "/Sec/tables/zsec-fleet-former/resources_by_zrn"
