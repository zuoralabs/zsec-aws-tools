import setuptools

setuptools.setup(
        name='zsec-aws-tools',
        packages=['zsec_aws_tools'],
        install_requires=['boto3', 'toolz'],
        tests_require=['toolz', 'pytest'],
        version='v0.1.21-alpha.1',
        )
