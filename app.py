from flask import render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from app import app, db
from app.models import Ticket, Reply, QuickReply

@app.route('/tickets')
@login_required
def tickets():
    tickets = Ticket.query.order_by(Ticket.last_activity.desc()).all()
    return render_template('tickets.html', tickets=tickets)

@app.route('/ticket/<int:ticket_id>')
@login_required
def ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    replies = Reply.query.filter_by(ticket_id=ticket_id).order_by(Reply.created_at.asc()).all()
    quick_replies = QuickReply.query.all()
    return render_template('ticket.html', ticket=ticket, replies=replies, quick_replies=quick_replies)

@app.route('/ticket/<int:ticket_id>/reply', methods=['POST'])
@login_required
def ticket_reply(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    message = request.form.get('message', '').strip()
    photo = request.files.get('photo')
    
    if not message and not photo:
        flash('Необходимо ввести сообщение или прикрепить фото', 'error')
        return redirect(url_for('ticket', ticket_id=ticket_id))
    
    photo_url = None
    if photo:
        filename = secure_filename(photo.filename)
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        photo.save(photo_path)
        photo_url = url_for('static', filename=f'uploads/{filename}')
    
    reply = Reply(
        ticket_id=ticket_id,
        message=message,
        photo_url=photo_url,
        is_admin=True
    )
    db.session.add(reply)
    
    ticket.last_activity = datetime.utcnow()
    ticket.last_message = message if message else 'Фото'
    
    db.session.commit()
    return redirect(url_for('ticket', ticket_id=ticket_id))

@app.route('/ticket/<int:ticket_id>/block', methods=['POST'])
@login_required
def block_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    ticket.is_blocked = True
    db.session.commit()
    return jsonify({'status': 'success'}) 