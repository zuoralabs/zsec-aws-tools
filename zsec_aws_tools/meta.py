from typing import Tuple, Generator

import botocore.model

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
