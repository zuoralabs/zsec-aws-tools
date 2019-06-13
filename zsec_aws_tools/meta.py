

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

    if ignore_when_missing_required_keys and not frozenset(kwargs.keys()).issubset(required_keys):
        return
    else:
        return fn(**filtered_kwargs)
