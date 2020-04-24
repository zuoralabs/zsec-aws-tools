import time
from zsec_aws_tools.async_tools import map_async


def test_1():
    def ff(x):
        time.sleep(.1)
        return x + 1

    expected = sum(map(ff, range(10)))
    assert sum(map_async(ff, range(10), sync=False)) == expected

    assert sum(map_async(ff, range(10), sync=True)) == expected

    assert sum(map_async(ff, range(10), max_concurrency=3, sync=True)) == expected
