import setuptools

setuptools.setup(
        name='zsec-aws-tools',
        packages=['zsec_aws_tools'],
        install_requires=['boto3'],
        tests_require=['toolz', 'pytest'],
        version='0.1.3',
        )
