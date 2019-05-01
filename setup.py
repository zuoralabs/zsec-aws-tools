import setuptools

setuptools.setup(
        name='zsec-aws-tools',
        packages=['zsec_aws_tools'],
        install_requires=['boto3'],
        test_requires=['toolz', 'pytest']
        )
