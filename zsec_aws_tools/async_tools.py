"""
Usage::

    def f1(x):
        import time
        time.sleep(SLEEP_TIME)
        print('hi', x)


    from functools import partial
    gather_and_run(asyncify(partial(f1, x)) for x in range(2))

    # alternatively
    maybe_asyncify_gather_and_run(partial(f1, x) for x in range(2))

"""

import asyncio
from functools import wraps, partial


async def asyncify(thunk):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, thunk)


def gather_and_run(fs):
    async def _inner():
        return await asyncio.gather(*fs)
    return asyncio.run(_inner())


def thunkify(fn):
    @wraps(fn)
    def thunkified(*args, **kwargs):
        return partial(fn, *args, **kwargs)

    return thunkified


def map_async(fn, iterable, sync=False):
    if sync:
        return map(fn, iterable)
    else:
        return gather_and_run(map(asyncify, (partial(fn, elt) for elt in iterable)))
