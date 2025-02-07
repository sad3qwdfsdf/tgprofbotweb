import os
from aiogram import Bot, Dispatcher, types
from dotenv import load_dotenv
from pathlib import Path
import asyncio
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

env_path = Path(__file__).parent / '.env'
load_dotenv(env_path)

token = os.getenv('BOT_TOKEN')
logger.debug(f"Using token: {token}")

async def main():
    bot = Bot(token=token)
    try:
        bot_info = await bot.get_me()
        logger.info(f"Bot info: {bot_info}")
        print(f"Bot successfully connected: @{bot_info.username}")
    except Exception as e:
        logger.error(f"Error connecting to bot: {e}")
    finally:
        await bot.close()

if __name__ == '__main__':
    asyncio.run(main()) 