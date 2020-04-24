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
from typing import Callable
from functools import wraps, partial


async def asyncify(fn, *args):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, fn, *args)


async def asyncify_with_limit(fn, max_concurrency, *args):
    with asyncio.Semaphore(max_concurrency):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, fn, *args)


def asyncify2(fn):
    @wraps(fn)
    def _fn(*args, **kwargs):
        @asyncify
        def thunk():
            return fn(*args, **kwargs)
        return thunk
    return _fn


def gather_and_run(fs):
    async def _inner():
        return await asyncio.gather(*fs)
    return asyncio.run(_inner())


def thunkify(fn):
    @wraps(fn)
    def thunkified(*args, **kwargs):
        return partial(fn, *args, **kwargs)

    return thunkified


def map_async(fn, iterable, *, max_concurrency: int = None, sync=False):
    if sync:
        return map(fn, iterable)
    else:
        if max_concurrency is not None:
            return gather_and_run(asyncify_with_limit(fn, max_concurrency, elt) for elt in iterable)
        else:
            return gather_and_run(asyncify(fn, elt) for elt in iterable)
