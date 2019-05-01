"""
Make cloudfront waf similar to waf-regional
"""

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

