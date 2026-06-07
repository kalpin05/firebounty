import aiohttp
import asyncio

async def fetch(session, url):

    try:
        async with session.get(url, timeout=5) as response:
            return url, response.status
    except:
        return url, None


async def run_async(urls):

    async with aiohttp.ClientSession() as session:

        tasks = [fetch(session, url) for url in urls]

        return await asyncio.gather(*tasks)