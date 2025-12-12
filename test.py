import os, argparse, csv, asyncio, aiohttp
from vendors import *

key = "63eb53e56495c76605ff6e666893b8b81b80c17bdd36fe62160c0ea99c79dfda"


async def main():
    async with aiohttp.ClientSession() as session:
        response = await vt_scan_url(session, "140.238.214.79:6443", key)
        print(response)


if __name__ == "__main__":
    asyncio.run(main())
