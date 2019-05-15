"""
Make cloudfront waf similar to waf-regional
"""

from typing import Iterable


def cloudfront_associate_web_acl(session, DistributionId, WebACLId):
    cloudfront = session.client('cloudfront')
    resp = cloudfront.get_distribution(Id=DistributionId)

    etag = resp['ETag']

    dist = resp['Distribution']['DistributionConfig']
    dist["WebACLId"] = WebACLId

    cloudfront.update_distribution(
        Id= DistributionId,
        DistributionConfig=dist,
        IfMatch=etag,
    )


def cloudfront_disassociate_web_acl(session, DistributionId):
    cloudfront_associate_web_acl(session,
                                 DistributionId=DistributionId,
                                 WebACLId='')


def cloudfront_distributions(session) -> Iterable[dict]:
    # also see cloudfront.list_distributions_by_web_acl_id
    cloudfront = session.client('cloudfront')

    resp = cloudfront.list_distributions()
    dist1 = resp['DistributionList']
    yield from dist1.get('Items', ())

    while dist1['Marker']:
        resp = cloudfront.list_distributions(Marker=resp['Marker'])
        dist1 = resp['DistributionList']
        if dist1['Quantity'] > 0:
            yield from dist1.get('Items', ())


def list_resources_for_web_acl(session, WebACLId) -> Iterable[dict]:
    """
    :param session:
    :param WebACLId: set to '' for resources with no associated Web ACL
    :return:
    """
    for dist in cloudfront_distributions(session):
        associated_webacl = dist['WebACLId']
        if associated_webacl == WebACLId:
            yield dist
