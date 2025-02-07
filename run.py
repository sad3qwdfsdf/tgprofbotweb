import asyncio
import uvicorn
import logging
from web_app import app
from bot import bot, dp
from database import init_db

logging.basicConfig(level=logging.INFO)

async def run_web():
    config = uvicorn.Config(app, host="0.0.0.0", port=8000)
    server = uvicorn.Server(config)
    await server.serve()

async def run_bot():
    try:
        await dp.start_polling()
    finally:
        await bot.close()

async def main():
    # Инициализируем базу данных
    init_db()
    logging.info("База данных инициализирована")
    
    # Запускаем бота и веб-сервер
    await asyncio.gather(
        run_web(),
        run_bot()
    )

if __name__ == "__main__":
    asyncio.run(main()) 