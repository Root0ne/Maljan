import asyncio

import asyncpg


async def main():
    try:
        conn = await asyncpg.connect("postgresql://maljan:maljan_dev@127.0.0.1:5432/maljan")
        print("Connection successful with maljan:maljan_dev")
        await conn.close()
    except Exception as e:
        print(f"Connection failed: {e}")


asyncio.run(main())
