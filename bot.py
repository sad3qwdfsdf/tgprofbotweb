import logging
from aiogram import Bot, Dispatcher, types
from aiogram.contrib.fsm_storage.memory import MemoryStorage
from aiogram.dispatcher.middlewares import BaseMiddleware
from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.handler import CancelHandler
from database import get_db, SessionLocal
from models import Ticket, User, Reply
import os
from dotenv import load_dotenv
from datetime import datetime
from sqlalchemy.orm import Session

# Загружаем переменные окружения
load_dotenv()

# Настраиваем логирование
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Инициализируем бота и диспетчер
bot = Bot(token=os.getenv("BOT_TOKEN"))
storage = MemoryStorage()
dp = Dispatcher(bot, storage=storage)

class DatabaseMiddleware(BaseMiddleware):
    def __init__(self):
        super().__init__()
        self.db = None

    async def on_pre_process_message(self, message: types.Message, data: dict):
        self.db = next(get_db())
        data['db'] = self.db

    async def on_post_process_message(self, message: types.Message, data_list: list, *args):
        if self.db:
            self.db.close()
            self.db = None

dp.middleware.setup(DatabaseMiddleware())

async def get_or_create_user(message: types.Message, db: Session) -> User:
    """Получает или создает пользователя"""
    user = db.query(User).filter(User.telegram_id == str(message.from_user.id)).first()
    if not user:
        username = message.from_user.username or f"user_{message.from_user.id}"
        first_name = message.from_user.first_name or ""
        last_name = message.from_user.last_name or ""
        
        user = User(
            username=username,
            telegram_id=str(message.from_user.id),
            first_name=first_name,
            last_name=last_name,
            is_blocked=False
        )
        db.add(user)
        db.commit()
    return user

async def get_or_create_ticket(user: User, db: Session) -> Ticket:
    """Получает активный тикет пользователя или создает новый"""
    ticket = db.query(Ticket).filter(
        Ticket.user_id == user.id,
        Ticket.is_blocked == False
    ).first()
    
    if not ticket:
        ticket = Ticket(
            title=f"Чат с {user.username or user.telegram_id}",
            description=f"Постоянный чат с пользователем {user.first_name or ''} {user.last_name or ''}",
            status="Активен",
            user_id=user.id,
            unread_count=0,
            is_blocked=False
        )
        db.add(ticket)
        db.commit()
    
    return ticket

@dp.message_handler(commands=['start'])
async def start(message: types.Message):
    db = SessionLocal()
    try:
        user = await get_or_create_user(message, db)
        if user.is_blocked:
            await message.reply("Извините, вы заблокированы.")
            return
            
        await get_or_create_ticket(user, db)
        await message.reply(
            "👋 Здравствуйте! Я бот технической поддержки.\n\n"
            "Отправляйте сообщения и фотографии, и команда поддержки ответит вам."
        )
    except Exception as e:
        logger.error(f"Ошибка при обработке команды start: {e}")
        await message.reply("Произошла ошибка. Пожалуйста, попробуйте позже.")
    finally:
        db.close()

@dp.message_handler(content_types=['photo'])
async def handle_photo(message: types.Message):
    """Обработчик фотографий"""
    db = SessionLocal()
    try:
        user = await get_or_create_user(message, db)
        if user.is_blocked:
            await message.reply("Извините, вы заблокированы.")
            return
            
        ticket = await get_or_create_ticket(user, db)
            
        # Получаем информацию о фото
        photo = message.photo[-1]  # Берем самое большое разрешение
        file_id = photo.file_id
        
        # Создаем новый ответ с фото
        reply = Reply(
            ticket_id=ticket.id,
            user_id=user.username or f"user_{user.telegram_id}",
            message=message.caption,  # Подпись к фото, если есть
            photo_file_id=file_id,
            is_read=False
        )
        db.add(reply)
        
        # Увеличиваем счетчик непрочитанных сообщений
        ticket.unread_count = ticket.unread_count + 1
        
        # Обновляем время последнего обновления тикета
        ticket.updated_at = datetime.utcnow()
        db.commit()
            
    except Exception as e:
        logger.error(f"Ошибка при обработке фото: {e}")
        await message.reply("Произошла ошибка при отправке фото. Пожалуйста, попробуйте позже.")
    finally:
        db.close()

@dp.message_handler()
async def handle_message(message: types.Message):
    """Обработчик всех текстовых сообщений"""
    db = SessionLocal()
    try:
        user = await get_or_create_user(message, db)
        if user.is_blocked:
            await message.reply("Извините, вы заблокированы.")
            return
            
        ticket = await get_or_create_ticket(user, db)
            
        # Создаем новый ответ
        reply = Reply(
            ticket_id=ticket.id,
            user_id=user.username or f"user_{user.telegram_id}",
            message=message.text,
            is_read=False
        )
        db.add(reply)
        
        # Увеличиваем счетчик непрочитанных сообщений
        ticket.unread_count = ticket.unread_count + 1
        
        # Обновляем время последнего обновления тикета
        ticket.updated_at = datetime.utcnow()
        db.commit()
            
    except Exception as e:
        logger.error(f"Ошибка при обработке сообщения: {e}")
        await message.reply("Произошла ошибка при отправке сообщения. Пожалуйста, попробуйте позже.")
    finally:
        db.close()

async def main():
    await dp.start_polling() 