from zsec_aws_tools.meta import CloudResourceMetaDescriptionBase
import boto3

session = boto3.Session(profile_name='test', region_name='us-east-1')

CloudResourceMetaDescriptionBase.set_table_name(session, table_name='resources_by_zrn_test', Overwrite=True)
CloudResourceMetaDescription = CloudResourceMetaDescriptionBase.attach_credentials(session)
CloudResourceMetaDescription.create_table(
    read_capacity_units=2,
    write_capacity_units=2,
    wait=True,
)
