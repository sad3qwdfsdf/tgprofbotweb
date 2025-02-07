import uvicorn
from web_app import app
from models import Base, User
from database import engine, SessionLocal
import os
from dotenv import load_dotenv
import logging

load_dotenv()

def init_db():
    # Создаем таблицы, если их нет
    Base.metadata.create_all(bind=engine)
    
    # Создаем сессию
    db = SessionLocal()
    try:
        # Проверяем, существует ли админ
        admin = db.query(User).filter(User.username == os.getenv("ADMIN_USERNAME")).first()
        if not admin:
            # Создаем админа
            admin = User(
                username=os.getenv("ADMIN_USERNAME"),
                password=os.getenv("ADMIN_PASSWORD")  # Пароль уже захеширован в .env
            )
            db.add(admin)
            db.commit()
            logging.info('Admin user created')
        
        logging.info('Database initialized')
    finally:
        db.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=8000) 