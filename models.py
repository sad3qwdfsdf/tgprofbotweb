from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String, nullable=True)
    telegram_id = Column(String, nullable=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_blocked = Column(Boolean, default=False)  # Флаг блокировки пользователя
    tickets = relationship('Ticket', back_populates='user')

class Ticket(Base):
    __tablename__ = 'tickets'
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(50), default='Активен')
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    unread_count = Column(Integer, default=0)  # Счетчик непрочитанных сообщений
    is_blocked = Column(Boolean, default=False)  # Флаг блокировки тикета
    
    user = relationship('User', back_populates='tickets')
    replies = relationship('Reply', back_populates='ticket', cascade='all, delete-orphan', order_by='Reply.created_at.asc()')

class Reply(Base):
    __tablename__ = 'replies'
    
    id = Column(Integer, primary_key=True, index=True)
    ticket_id = Column(Integer, ForeignKey('tickets.id', ondelete='CASCADE'))
    user_id = Column(String, ForeignKey('users.username'))
    message = Column(Text, nullable=True)  # Может быть NULL если есть фото
    photo_url = Column(String, nullable=True)  # URL или путь к фото
    photo_file_id = Column(String, nullable=True)  # ID файла в Telegram
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_read = Column(Boolean, default=False)  # Флаг прочтения
    is_admin = Column(Boolean, default=False)  # Флаг сообщения от администратора
    
    ticket = relationship('Ticket', back_populates='replies')
    user = relationship('User', backref='replies')

class QuickReply(Base):
    __tablename__ = 'quick_replies'
    
    id = Column(Integer, primary_key=True, index=True)
    button_text = Column(String(100), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_active = Column(Boolean, default=True)
    position = Column(Integer, default=0)  # Поле для сохранения порядка 