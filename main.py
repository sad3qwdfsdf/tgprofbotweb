import logging
from bot import dp
from aiogram import executor
from models import Base
from database import engine
import os
from dotenv import load_dotenv

load_dotenv()

def init_db():
    # Создаем таблицы, если их нет
    Base.metadata.create_all(bind=engine)
    logging.info('Database initialized')

async def on_startup(dp):
    init_db()
    logging.info('Bot started')

def main():
    # Запускаем бота
    executor.start_polling(
        dispatcher=dp,
        on_startup=on_startup,
        skip_updates=True
    )

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main() 