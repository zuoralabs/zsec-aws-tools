# Benchmarks

## `list_with_tags`

.. default-role:: code

Informal benchmark of `list_with_tags` using IPython, where the `account:region` has 9 buckets::

    timeit list(print(bucket.ztid) for bucket in zs3.Bucket.list_with_tags(boto3.Session()))

    -> 1.75 s ± 898 ms per loop (mean ± std. dev. of 7 runs, 1 loop each)

    timeit list(print(bucket.ztid) for bucket in zs3.Bucket.list_with_tags(boto3.Session(), sync=True))

    -> 9.31 s ± 2.73 s per loop (mean ± std. dev. of 7 runs, 1 loop each)

(Note: most of the time is waiting for AWS API response. Region was us-west-1.)

