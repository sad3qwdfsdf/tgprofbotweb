from fastapi import FastAPI, Depends, HTTPException, status, Request, Form, Header, Cookie, Body, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from datetime import timedelta, datetime
import os
from dotenv import load_dotenv
from database import get_db, SessionLocal
from models import Ticket, Reply, User, QuickReply
from auth import (
    verify_password,
    create_access_token,
    get_current_user,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from bot import bot
from typing import Optional
from jose import JWTError, jwt
import logging
from sqlalchemy.sql import func
import json
import secrets
from starlette.middleware.base import BaseHTTPMiddleware

# Настройка логгера
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            csrf_token = request.headers.get("X-CSRF-Token")
            cookie_token = request.cookies.get("csrf_token")
            
            if not csrf_token or not cookie_token or csrf_token != cookie_token:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF token missing or invalid"}
                )
        
        response = await call_next(request)
        return response

def escapejs(value):
    """Экранирует строку для безопасного использования в JavaScript"""
    return json.dumps(str(value))[1:-1]

load_dotenv()

app = FastAPI()

# Добавляем CSRF middleware
app.add_middleware(CSRFMiddleware)

# Добавляем CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Подключаем статические файлы
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Регистрируем фильтр escapejs
templates.env.filters["escapejs"] = escapejs

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

async def verify_token(authorization: Optional[str] = None) -> Optional[str]:
    if not authorization:
        return None
    
    # Если токен в куки, он не будет иметь префикс "Bearer "
    token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
    
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=["HS256"])
        username = payload.get("sub")
        if username != os.getenv("ADMIN_USERNAME"):
            return None
        return username
    except JWTError:
        return None

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    db = SessionLocal()
    try:
        # Получаем счетчики
        active_chats_count, blocked_users_count = await get_counters(db)
        
        # Генерируем CSRF токен
        csrf_token = secrets.token_urlsafe(32)
        
        # Создаем ответ
        response = templates.TemplateResponse(
            "login.html", 
            {
                "request": request,
                "active_chats_count": active_chats_count,
                "blocked_users_count": blocked_users_count,
                "csrf_token": csrf_token
            }
        )
        
        # Устанавливаем CSRF токен в куки
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            httponly=True,
            samesite="strict"
        )
        
        return response
    finally:
        db.close()

@app.post("/token")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    # Проверяем CSRF токен
    csrf_token = request.headers.get("X-CSRF-Token")
    cookie_token = request.cookies.get("csrf_token")
    
    if not csrf_token or not cookie_token or csrf_token != cookie_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing or invalid"
        )
    
    print(f"Login attempt: username={form_data.username}, password={form_data.password}")
    stored_password = os.getenv("ADMIN_PASSWORD")
    print(f"Stored password hash: {stored_password}")
    
    if form_data.username != os.getenv("ADMIN_USERNAME") or \
       not verify_password(form_data.password, stored_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username},
        expires_delta=access_token_expires
    )
    
    response = JSONResponse({"access_token": access_token, "token_type": "bearer"})
    response.set_cookie(
        key="authorization",
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/"
    )
    return response

@app.get("/")
async def root(request: Request, authorization: str = Cookie(default=None)):
    db = SessionLocal()
    try:
        # Получаем счетчики
        active_chats_count, blocked_users_count = await get_counters(db)
        
        if not authorization:
            return templates.TemplateResponse(
                "login.html", 
                {
                    "request": request,
                    "active_chats_count": active_chats_count,
                    "blocked_users_count": blocked_users_count
                }
            )
        
        username = await verify_token(authorization)
        if not username:
            return templates.TemplateResponse(
                "login.html", 
                {
                    "request": request,
                    "active_chats_count": active_chats_count,
                    "blocked_users_count": blocked_users_count
                }
            )
        
        return RedirectResponse(url="/tickets", status_code=303)
    finally:
        db.close()

def format_user_info(user: User) -> str:
    """Форматирует информацию о пользователе"""
    if not user:
        return "Неизвестный пользователь"
        
    parts = []
    if user.first_name or user.last_name:
        name_parts = [p for p in [user.first_name, user.last_name] if p]
        parts.append(" ".join(name_parts))
    if user.username:
        parts.append(f"@{user.username}")
    elif user.telegram_id:
        parts.append(f"id: {user.telegram_id}")
        
    return " | ".join(parts) if parts else "Пользователь без имени"

async def get_counters(db):
    """Получает счетчики для активных и заблокированных чатов"""
    active_chats_count = db.query(Ticket).filter(Ticket.is_blocked == False).count()
    blocked_users_count = db.query(User).filter(User.is_blocked == True).count()
    return active_chats_count, blocked_users_count

@app.get("/tickets")
async def tickets(
    request: Request,
    chat: Optional[int] = None,
    format: Optional[str] = None,
    authorization: str = Cookie(default=None),
    csrf_token: str = Cookie(default=None)
):
    if not authorization:
        return RedirectResponse(url="/login", status_code=303)
    
    username = await verify_token(authorization)
    if not username:
        return RedirectResponse(url="/login", status_code=303)
    
    db = SessionLocal()
    try:
        # Получаем только активные чаты с пользователями
        tickets = db.query(Ticket).filter(
            Ticket.is_blocked == False
        ).order_by(Ticket.updated_at.desc()).all()
        
        # Добавляем информацию о последнем сообщении для активных тикетов
        for ticket in tickets:
            last_reply = db.query(Reply).filter(Reply.ticket_id == ticket.id).order_by(Reply.created_at.desc()).first()
            if last_reply:
                if last_reply.photo_file_id:
                    setattr(ticket, 'last_message', "[Фото]" + (f": {last_reply.message}" if last_reply.message else ""))
                else:
                    setattr(ticket, 'last_message', last_reply.message)
                setattr(ticket, 'last_activity', last_reply.created_at)
            else:
                setattr(ticket, 'last_message', "Нет сообщений")
                setattr(ticket, 'last_activity', ticket.created_at)
            
            # Получаем информацию о пользователе
            user = db.query(User).filter(User.id == ticket.user_id).first()
            setattr(ticket, 'user_info', format_user_info(user))
            
            # Подсчитываем количество непрочитанных сообщений
            unread_count = db.query(Reply).filter(
                Reply.ticket_id == ticket.id,
                Reply.is_read == False,
                Reply.is_admin == False
            ).count()
            setattr(ticket, 'unread_count', unread_count)
        
        # Если запрошен JSON формат, возвращаем данные в JSON
        if format == 'json':
            return {
                "tickets": [
                    {
                        "id": ticket.id,
                        "user_info": ticket.user_info,
                        "last_message": ticket.last_message,
                        "last_activity": ticket.last_activity.isoformat() if ticket.last_activity else None,
                        "unread_count": ticket.unread_count
                    }
                    for ticket in tickets
                ]
            }
        
        # Если указан конкретный чат, получаем его детали
        selected_ticket = None
        if chat:
            selected_ticket = db.query(Ticket).filter(Ticket.id == chat).first()
            if selected_ticket:
                # Получаем все сообщения выбранного чата
                replies = db.query(Reply).filter(Reply.ticket_id == chat).order_by(Reply.created_at.asc()).all()
                
                # Помечаем сообщения администратора и получаем URL фотографий
                admin_username = os.getenv("ADMIN_USERNAME")
                for reply in replies:
                    reply.is_admin = (reply.user_id == admin_username)
                    if not reply.is_read:
                        reply.is_read = True
                    # Если есть фото, получаем его URL
                    if reply.photo_file_id:
                        try:
                            file_info = await bot.get_file(reply.photo_file_id)
                            reply.photo_url = f"https://api.telegram.org/file/bot{os.getenv('BOT_TOKEN')}/{file_info.file_path}"
                        except Exception as e:
                            logger.error(f"Ошибка получения URL фото: {e}")
                            reply.photo_url = None
                
                setattr(selected_ticket, 'replies', replies)
                selected_ticket.unread_count = 0
                db.commit()
        
        # Получаем быстрые ответы
        quick_replies = db.query(QuickReply).filter(
            QuickReply.is_active == True
        ).order_by(QuickReply.position.asc()).all()
        
        # Получаем счетчики
        active_chats_count, blocked_users_count = await get_counters(db)
        
        # Создаем ответ
        response = templates.TemplateResponse(
            "tickets.html", 
            {
                "request": request, 
                "tickets": tickets,
                "selected_ticket": selected_ticket,
                "quick_replies": quick_replies,
                "active_chats_count": active_chats_count,
                "blocked_users_count": blocked_users_count,
                "csrf_token": csrf_token or secrets.token_urlsafe(32)
            }
        )
        
        # Если CSRF токен не установлен, устанавливаем его
        if not csrf_token:
            response.set_cookie(
                key="csrf_token",
                value=response.context["csrf_token"],
                httponly=True,
                samesite="strict"
            )
        
        return response
    except Exception as e:
        logger.error(f"Error getting tickets: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.get("/ticket/{ticket_id}")
async def ticket(request: Request, ticket_id: int, authorization: str = Cookie(default=None)):
    if not authorization:
        return RedirectResponse(url="/login", status_code=303)
    
    username = await verify_token(authorization)
    if not username:
        return RedirectResponse(url="/login", status_code=303)
    
    db = SessionLocal()
    try:
        ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Чат не найден")
        
        # Получаем информацию о пользователе
        user = db.query(User).filter(User.id == ticket.user_id).first()
        ticket.user_info = format_user_info(user)
        
        # Получаем все сообщения
        replies = db.query(Reply).filter(Reply.ticket_id == ticket.id).order_by(Reply.created_at.asc()).all()
        
        # Помечаем сообщения администратора и получаем URL фотографий
        admin_username = os.getenv("ADMIN_USERNAME")
        for reply in replies:
            reply.is_admin = (reply.user_id == admin_username)
            if not reply.is_read:
                reply.is_read = True
            # Если есть фото, получаем его URL
            if reply.photo_file_id:
                try:
                    file_info = await bot.get_file(reply.photo_file_id)
                    reply.photo_url = f"https://api.telegram.org/file/bot{os.getenv('BOT_TOKEN')}/{file_info.file_path}"
                except Exception as e:
                    logger.error(f"Ошибка получения URL фото: {e}")
                    reply.photo_url = None
        
        ticket.unread_count = 0
        db.commit()
        
        # Получаем быстрые ответы
        quick_replies = db.query(QuickReply).filter(QuickReply.is_active == True).order_by(QuickReply.created_at.desc()).all()
        
        return templates.TemplateResponse(
            "ticket.html", 
            {
                "request": request, 
                "ticket": ticket,
                "replies": replies,
                "admin_username": admin_username,
                "quick_replies": quick_replies
            }
        )
    except Exception as e:
        logger.error(f"Error getting ticket: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.get("/ticket/{ticket_id}/messages")
async def get_chat_messages(
    ticket_id: int,
    authorization: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401)
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401)
    
    db = SessionLocal()
    try:
        ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Чат не найден")
        
        # Получаем информацию о пользователе
        user = db.query(User).filter(User.id == ticket.user_id).first()
        user_info = format_user_info(user)
        
        # Получаем все сообщения
        replies = db.query(Reply).filter(Reply.ticket_id == ticket.id).order_by(Reply.created_at.asc()).all()
        
        # Помечаем сообщения администратора и получаем URL фотографий
        admin_username = os.getenv("ADMIN_USERNAME")
        replies_data = []
        for reply in replies:
            reply_data = {
                "id": reply.id,
                "message": reply.message,
                "created_at": reply.created_at.isoformat(),
                "is_admin": (reply.user_id == admin_username),
                "is_read": reply.is_read
            }
            
            if not reply.is_read:
                reply.is_read = True
                
            # Если есть фото, получаем его URL
            if reply.photo_file_id:
                try:
                    file_info = await bot.get_file(reply.photo_file_id)
                    reply_data["photo_url"] = f"https://api.telegram.org/file/bot{os.getenv('BOT_TOKEN')}/{file_info.file_path}"
                except Exception as e:
                    logger.error(f"Ошибка получения URL фото: {e}")
                    reply_data["photo_url"] = None
            
            replies_data.append(reply_data)
        
        # Сбрасываем счетчик непрочитанных сообщений
        ticket.unread_count = 0
        db.commit()
        
        return {
            "user_info": user_info,
            "status": ticket.status,
            "replies": replies_data
        }
    except Exception as e:
        logger.error(f"Error getting chat messages: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/ticket/{ticket_id}/reply")
async def reply_to_ticket(
    ticket_id: int,
    message: str = Form(None),
    photo: UploadFile = File(None),
    authorization: str = Cookie(default=None),
    request: Request = None
):
    if not authorization:
        raise HTTPException(status_code=401)
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401)
    
    if not message and not photo:
        raise HTTPException(status_code=400, detail="Необходимо отправить сообщение или фото")
    
    db = SessionLocal()
    try:
        ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Чат не найден")
        
        photo_file_id = None
        photo_url = None
        if photo and photo.filename:
            try:
                # Читаем содержимое файла
                contents = await photo.read()
                # Отправляем фото в Telegram и получаем file_id
                sent_photo = await bot.send_photo(
                    chat_id=int(ticket.user.telegram_id),
                    photo=contents,
                    caption=message or ""
                )
                # Сохраняем file_id
                photo_file_id = sent_photo.photo[-1].file_id
                # Получаем URL фото
                file_info = await bot.get_file(photo_file_id)
                photo_url = f"https://api.telegram.org/file/bot{os.getenv('BOT_TOKEN')}/{file_info.file_path}"
            except Exception as e:
                logger.error(f"Ошибка при отправке фото: {e}")
                raise HTTPException(status_code=500, detail="Ошибка при отправке фото")
        
        # Создаем новый ответ
        new_reply = Reply(
            ticket_id=ticket_id,
            user_id=username,
            message=message,
            photo_file_id=photo_file_id,
            photo_url=photo_url,
            is_read=True,
            is_admin=True
        )
        db.add(new_reply)
        
        # Обновляем время последнего обновления тикета
        ticket.updated_at = datetime.utcnow()
        db.commit()
        
        # Если нет фото, отправляем текстовое сообщение
        if not photo_file_id and message:
            try:
                await bot.send_message(
                    chat_id=int(ticket.user.telegram_id),
                    text=f"📩 Новое сообщение от поддержки:\n\n{message}"
                )
                logger.info(f"Уведомление отправлено пользователю {ticket.user.telegram_id}")
            except Exception as e:
                logger.error(f"Ошибка отправки уведомления в Telegram: {e}")
        
        # Проверяем, является ли запрос AJAX
        is_ajax = request and request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if is_ajax:
            return {
                "id": new_reply.id,
                "message": message,
                "photo_url": photo_url,
                "created_at": new_reply.created_at.isoformat(),
                "is_admin": True
            }
        
        return RedirectResponse(url=f"/ticket/{ticket_id}", status_code=303)
    except Exception as e:
        logger.error(f"Ошибка при отправке ответа: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if photo:
            await photo.close()
        db.close()

@app.post("/ticket/{ticket_id}/status")
async def change_ticket_status(
    ticket_id: int,
    status: dict = Body(...),
    authorization: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401)
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401)
    
    db = SessionLocal()
    try:
        ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Тикет не найден")
        
        old_status = ticket.status
        ticket.status = status["status"]
        db.commit()
        
        # Получаем пользователя, создавшего тикет
        user = db.query(User).filter(User.id == ticket.user_id).first()
        if user and user.telegram_id:
            # Отправляем уведомление в Telegram
            try:
                await bot.send_message(
                    chat_id=user.telegram_id,
                    text=f"🔄 Статус вашего тикета #{ticket.id} изменен\n\n"
                         f"Тема: {ticket.title}\n"
                         f"Старый статус: {old_status}\n"
                         f"Новый статус: {ticket.status}"
                )
                logger.info(f"Уведомление об изменении статуса отправлено пользователю {user.telegram_id}")
            except Exception as e:
                logger.error(f"Ошибка отправки уведомления в Telegram: {e}")
        
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Ошибка при изменении статуса: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/ticket/{ticket_id}/delete")
async def delete_ticket(
    ticket_id: int,
    authorization: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401)
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401)
    
    db = SessionLocal()
    try:
        ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Чат не найден")
        
        # Помечаем тикет как удаленный
        ticket.is_deleted = True
        db.commit()
        
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Ошибка при удалении чата: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/ticket/{ticket_id}/mark-read")
async def mark_messages_read(
    ticket_id: int,
    authorization: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401)
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401)
    
    db = SessionLocal()
    try:
        # Отмечаем все сообщения как прочитанные
        db.query(Reply).filter(
            Reply.ticket_id == ticket_id,
            Reply.is_read == False
        ).update({"is_read": True})
        
        # Обнуляем счетчик непрочитанных сообщений
        ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
        if ticket:
            ticket.unread_count = 0
            
        db.commit()
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Ошибка при отметке сообщений как прочитанных: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/ticket/{ticket_id}/block")
async def block_ticket(
    ticket_id: int,
    authorization: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401)
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401)
    
    db = SessionLocal()
    try:
        ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Чат не найден")
        
        # Блокируем тикет и пользователя
        ticket.is_blocked = True
        user = db.query(User).filter(User.id == ticket.user_id).first()
        if user:
            user.is_blocked = True
            
            # Блокируем все чаты пользователя
            other_tickets = db.query(Ticket).filter(Ticket.user_id == user.id).all()
            for other_ticket in other_tickets:
                other_ticket.is_blocked = True
            
            # Отправляем уведомление пользователю
            try:
                await bot.send_message(
                    chat_id=int(user.telegram_id),
                    text="⛔️ Ваш аккаунт был заблокирован администратором. Вы больше не можете отправлять сообщения."
                )
                logger.info(f"Уведомление о блокировке отправлено пользователю {user.telegram_id}")
            except Exception as e:
                logger.error(f"Error sending block notification to Telegram: {e}")
                # Не выбрасываем исключение, так как блокировка уже выполнена
        
        db.commit()
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Ошибка при блокировке чата: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/ticket/{ticket_id}/unblock")
async def unblock_ticket(
    ticket_id: int,
    authorization: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401)
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401)
    
    db = SessionLocal()
    try:
        ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Чат не найден")
        
        # Разблокируем тикет и пользователя
        ticket.is_blocked = False
        user = db.query(User).filter(User.id == ticket.user_id).first()
        if user:
            user.is_blocked = False
            
            # Отправляем уведомление пользователю
            try:
                await bot.send_message(
                    chat_id=int(user.telegram_id),
                    text="✅ Ваш чат был разблокирован администратором. Вы снова можете отправлять сообщения."
                )
            except Exception as e:
                logger.error(f"Ошибка отправки уведомления о разблокировке: {e}")
        
        db.commit()
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Ошибка при разблокировке чата: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.get("/blocked-users")
async def blocked_users(request: Request, authorization: str = Cookie(default=None), csrf_token: str = Cookie(default=None)):
    if not authorization:
        return RedirectResponse(url="/login", status_code=303)
    
    username = await verify_token(authorization)
    if not username:
        return RedirectResponse(url="/login", status_code=303)
    
    db = SessionLocal()
    try:
        # Получаем всех заблокированных пользователей вместе с их тикетами
        users = db.query(User).filter(
            User.is_blocked == True
        ).options(selectinload(User.tickets)).order_by(User.created_at.desc()).all()
        
        # Получаем счетчики
        active_chats_count, blocked_users_count = await get_counters(db)
        
        # Создаем ответ
        response = templates.TemplateResponse(
            "blocked_users.html",
            {
                "request": request,
                "users": users,
                "active_chats_count": active_chats_count,
                "blocked_users_count": blocked_users_count,
                "csrf_token": csrf_token or secrets.token_urlsafe(32)
            }
        )
        
        # Если CSRF токен не установлен, устанавливаем его
        if not csrf_token:
            response.set_cookie(
                key="csrf_token",
                value=response.context["csrf_token"],
                httponly=True,
                samesite="strict"
            )
        
        return response
    except Exception as e:
        logger.error(f"Error getting blocked users: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/user/{user_id}/unblock")
async def unblock_user(
    user_id: int,
    request: Request,
    authorization: str = Cookie(default=None),
    csrf_token: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401)
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401)
    
    # Проверяем CSRF токен
    request_csrf_token = request.headers.get("X-CSRF-Token")
    if not csrf_token or not request_csrf_token or csrf_token != request_csrf_token:
        raise HTTPException(
            status_code=403,
            detail="CSRF token missing or invalid"
        )
    
    db = SessionLocal()
    try:
        # Разблокируем пользователя
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        
        user.is_blocked = False
        
        # Разблокируем все чаты пользователя
        tickets = db.query(Ticket).filter(Ticket.user_id == user.id).all()
        for ticket in tickets:
            ticket.is_blocked = False
        
        db.commit()
        
        # Отправляем уведомление пользователю
        try:
            await bot.send_message(
                chat_id=int(user.telegram_id),
                text="✅ Ваш аккаунт был разблокирован администратором. Вы снова можете отправлять сообщения."
            )
        except Exception as e:
            logger.error(f"Ошибка отправки уведомления о разблокировке: {e}")
        
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Ошибка при разблокировке пользователя: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.get("/quick-replies")
async def quick_replies_page(request: Request, authorization: str = Cookie(default=None), csrf_token: str = Cookie(default=None)):
    if not authorization:
        return RedirectResponse(url="/login", status_code=303)
    
    username = await verify_token(authorization)
    if not username:
        return RedirectResponse(url="/login", status_code=303)
    
    db = SessionLocal()
    try:
        # Изменяем сортировку на position
        quick_replies = db.query(QuickReply).filter(
            QuickReply.is_active == True
        ).order_by(QuickReply.position.asc()).all()
        
        # Получаем счетчики
        active_chats_count, blocked_users_count = await get_counters(db)
        
        # Создаем ответ
        response = templates.TemplateResponse(
            "quick_replies.html",
            {
                "request": request,
                "quick_replies": quick_replies,
                "active_chats_count": active_chats_count,
                "blocked_users_count": blocked_users_count,
                "csrf_token": csrf_token or secrets.token_urlsafe(32)
            }
        )
        
        # Если CSRF токен не установлен, устанавливаем его
        if not csrf_token:
            response.set_cookie(
                key="csrf_token",
                value=response.context["csrf_token"],
                httponly=True,
                samesite="strict"
            )
        
        return response
    except Exception as e:
        logger.error(f"Error getting quick replies: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/quick-replies/add")
async def add_quick_reply(
    request: Request,
    button_text: str = Form(...),
    message: str = Form(...),
    authorization: str = Cookie(default=None),
    csrf_token: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401)
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401)
    
    # Проверяем CSRF токен
    request_csrf_token = request.headers.get("X-CSRF-Token")
    if not csrf_token or not request_csrf_token or csrf_token != request_csrf_token:
        raise HTTPException(
            status_code=403,
            detail="CSRF token missing or invalid"
        )
    
    db = SessionLocal()
    try:
        # Получаем максимальную позицию
        max_position = db.query(func.max(QuickReply.position)).scalar() or -1
        
        quick_reply = QuickReply(
            button_text=button_text,
            message=message,
            is_active=True,
            position=max_position + 1
        )
        db.add(quick_reply)
        db.commit()
        return RedirectResponse(url="/quick-replies", status_code=303)
    except Exception as e:
        logger.error(f"Error adding quick reply: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/quick-replies/reorder")
async def reorder_quick_replies(
    request: Request,
    data: dict = Body(...),
    authorization: str = Cookie(default=None),
    csrf_token: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401)
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401)
    
    # Проверяем CSRF токен
    request_csrf_token = request.headers.get("X-CSRF-Token")
    if not csrf_token or not request_csrf_token or csrf_token != request_csrf_token:
        raise HTTPException(
            status_code=403,
            detail="CSRF token missing or invalid"
        )
    
    db = SessionLocal()
    try:
        # Обновляем позиции быстрых ответов
        order = data.get('order', [])
        for item in order:
            reply_id = int(item['id'])
            position = int(item['position'])
            
            reply = db.query(QuickReply).filter(
                QuickReply.id == reply_id,
                QuickReply.is_active == True
            ).first()
            
            if reply:
                reply.position = position
        
        db.commit()
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error reordering quick replies: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/quick-replies/{reply_id}/delete")
async def delete_quick_reply(
    reply_id: int,
    request: Request,
    authorization: str = Cookie(default=None),
    csrf_token: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401)
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401)
    
    # Проверяем CSRF токен
    request_csrf_token = request.headers.get("X-CSRF-Token")
    if not csrf_token or not request_csrf_token or csrf_token != request_csrf_token:
        raise HTTPException(
            status_code=403,
            detail="CSRF token missing or invalid"
        )
    
    db = SessionLocal()
    try:
        reply = db.query(QuickReply).filter(QuickReply.id == reply_id).first()
        if not reply:
            raise HTTPException(status_code=404, detail="Quick reply not found")
        
        db.delete(reply)
        db.commit()
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error deleting quick reply: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/quick-replies/{reply_id}/edit")
async def edit_quick_reply(
    reply_id: int,
    request: Request,
    button_text: str = Form(...),
    message: str = Form(...),
    authorization: str = Cookie(default=None),
    csrf_token: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401)
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401)
    
    # Проверяем CSRF токен
    request_csrf_token = request.headers.get("X-CSRF-Token")
    if not csrf_token or not request_csrf_token or csrf_token != request_csrf_token:
        raise HTTPException(
            status_code=403,
            detail="CSRF token missing or invalid"
        )
    
    db = SessionLocal()
    try:
        reply = db.query(QuickReply).filter(QuickReply.id == reply_id).first()
        if not reply:
            raise HTTPException(status_code=404, detail="Quick reply not found")
        
        reply.button_text = button_text
        reply.message = message
        db.commit()
        
        return RedirectResponse(url="/quick-replies", status_code=303)
    except Exception as e:
        logger.error(f"Error editing quick reply: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.get("/user/{user_id}/info")
async def get_user_info(
    user_id: int,
    authorization: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401)
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401)
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        
        return {
            "username": user.username,
            "first_name": user.first_name or "",
            "last_name": user.last_name or "",
            "telegram_id": user.telegram_id,
            "created_at": user.created_at.isoformat(),
            "tickets_count": len(user.tickets)
        }
    except Exception as e:
        logger.error(f"Error getting user info: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/send_message")
async def send_message(
    request: Request,
    data: dict = Body(...),
    authorization: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401, detail="Не авторизован")
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401, detail="Не авторизован")
    
    ticket_id = data.get("ticket_id")
    message = data.get("message")
    
    if not ticket_id or not message:
        raise HTTPException(status_code=400, detail="Отсутствуют необходимые параметры")
    
    db = SessionLocal()
    try:
        # Получаем тикет вместе с информацией о пользователе
        ticket = db.query(Ticket).join(User).filter(Ticket.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Тикет не найден")
        
        # Создаем новое сообщение
        reply = Reply(
            ticket_id=ticket_id,
            user_id=username,  # Используем имя админа как user_id
            message=message,
            is_read=True  # Сообщения от админа всегда прочитаны
        )
        db.add(reply)
        
        # Обновляем время последней активности тикета
        ticket.updated_at = datetime.utcnow()
        
        db.commit()
        
        # Отправляем сообщение пользователю через бота
        try:
            await bot.send_message(
                chat_id=int(ticket.user.telegram_id),  # Используем telegram_id из связанного объекта User
                text=f"📩 Новое сообщение от поддержки:\n\n{message}"
            )
        except Exception as e:
            logger.error(f"Error sending message to Telegram: {e}")
            # Не выбрасываем исключение, так как сообщение уже сохранено в БД
        
        return {"success": True}
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        raise HTTPException(status_code=500, detail="Ошибка при отправке сообщения")
    finally:
        db.close()

@app.post("/block_user")
async def block_user(
    request: Request,
    data: dict = Body(...),
    authorization: str = Cookie(default=None)
):
    if not authorization:
        raise HTTPException(status_code=401, detail="Не авторизован")
    
    username = await verify_token(authorization)
    if not username:
        raise HTTPException(status_code=401, detail="Не авторизован")
    
    ticket_id = data.get("ticket_id")
    if not ticket_id:
        raise HTTPException(status_code=400, detail="Отсутствует ID тикета")
    
    db = SessionLocal()
    try:
        # Получаем тикет вместе с информацией о пользователе
        ticket = db.query(Ticket).join(User).filter(Ticket.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Тикет не найден")
        
        # Получаем пользователя
        user = ticket.user
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        
        # Блокируем пользователя и тикет
        user.is_blocked = True
        ticket.is_blocked = True
        
        # Блокируем все тикеты пользователя
        other_tickets = db.query(Ticket).filter(Ticket.user_id == user.id).all()
        for other_ticket in other_tickets:
            other_ticket.is_blocked = True
        
        db.commit()
        
        # Отправляем уведомление пользователю
        try:
            await bot.send_message(
                chat_id=int(user.telegram_id),
                text="⛔️ Ваш аккаунт был заблокирован администратором. Вы больше не можете отправлять сообщения."
            )
            logger.info(f"Уведомление о блокировке отправлено пользователю {user.telegram_id}")
        except Exception as e:
            logger.error(f"Error sending block notification to Telegram: {e}")
            # Не выбрасываем исключение, так как блокировка уже выполнена
        
        return {"success": True}
    except Exception as e:
        logger.error(f"Error blocking user: {e}")
        raise HTTPException(status_code=500, detail="Ошибка при блокировке пользователя")
    finally:
        db.close() 