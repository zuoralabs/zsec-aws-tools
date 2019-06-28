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


async def asyncify(thunk):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, thunk)


def gather_and_run(fs):
    async def _inner():
        return await asyncio.gather(*fs)
    return asyncio.run(_inner())


def maybe_asyncify_gather_and_run(fs, sync=False):
    if sync:
        return (f() for f in fs)
    else:
        return gather_and_run(map(asyncify, fs))
