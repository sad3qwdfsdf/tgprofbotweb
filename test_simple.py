from aiogram import Bot
import asyncio

TOKEN = "7710950782:AAF96Z1ef_9d_46jqGJxcSj0z2qkacr5vO4"

async def main():
    bot = Bot(token=TOKEN)
    try:
        me = await bot.get_me()
        print(f"Successfully connected to bot: @{me.username}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await bot.close()

if __name__ == '__main__':
    asyncio.run(main()) 