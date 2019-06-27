.. default-role:: code

==============
zsec-aws-tools
==============

A library for making AWS API nicer to use.


Installation
============

.. code:: bash

    pip install git+https://github.com/zuoralabs/zsec-aws-tools.git@master

or add to `install_requires` in `setup.py` for your module.

.. code:: py

    install_requires = [
        'zsec-aws-tools @ git+https://github.com/zuoralabs/zsec-aws-tools.git@master',
    ]


Usage
=====

The main pattern is to use `AWSResource` objects to describe resources and then
to call `AWSResource.put` when you want to make the remote environment match your code.
`put` is idempotent.

An `AWSResource` takes the following initialization params:

- `session`: AWS session.
- `region_name`: AWS region name, such as `us-east-1`.
- `ztid`: A UUID used to identify resources over name changes. For example, to rename a bucket,
  the IAM role needs to be deleted and a copy with the new name created. Using the UUID, you
  can still identify the role in your code with the new actualized role when you change the
  name.
- `name` or `index_id`: the `index_id` is used to identify the resource for describing
  the resource. The AWS API is inconsistent about how it identifies resources. For example when you
  call `GetRole`, you pass the `RoleName`, but for `GetPolicy`, you pass the `PolicyArn`.
  You can check the `index_id_name` attribute to see what to pass as `index_id`. For example,
  `Role.index_id_name = "RoleName"` and `Policy.index_id_name = "PolicyArn"`.
- `config`: a dictionary containing the configuration for the resource. This usually takes
  the same input as boto3 creation function for the resource type. This is used
  by `AWSResource.put`. More details below.

The most complicated part is `config`, which declares what you want the resource to look like
after `put`. If any of the values in the `config` dictionary are callable, they will
be called on the resource before being used in a call to the AWS API. This is useful
when the config depends on an attribute of the resource itself. For example, a resource
policy may require the resource ARN, which is most convenient to calculate after the resource
has been defined.
