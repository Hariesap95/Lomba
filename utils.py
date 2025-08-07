import functools
import hashlib
from datetime import datetime
from flask import session, request, flash, redirect, url_for
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO
from app import db
from models import User, AuditLog, Competition, Team, Score, Question, QuestionScore, ScoringLabel

def require_login(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        
        # Verify session token for single device login
        user = User.query.get(session['user_id'])
        if not user or user.session_token != session.get('session_token'):
            session.clear()
            flash('Your session has expired. Please log in again.', 'error')
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def require_role(allowed_roles):
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]
    
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') not in allowed_roles:
                flash('You do not have permission to access this page', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_user_action(user_id, action, resource_type, resource_id=None, details=None):
    """Log user actions for audit trail"""
    try:
        audit_log = AuditLog()
        audit_log.user_id = user_id
        audit_log.action = action
        audit_log.resource_type = resource_type
        audit_log.resource_id = resource_id
        audit_log.details = details
        audit_log.ip_address = request.remote_addr
        audit_log.user_agent = request.headers.get('User-Agent')
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        # Log to application logs
        print(f"Failed to log user action: {e}")

def generate_pdf_report(competition_id):
    """Generate PDF report for competition"""
    competition = Competition.query.get(competition_id)
    if not competition:
        return None
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=30,
        alignment=1  # Center alignment
    )
    
    # Title
    title = Paragraph(f"Competition Report: {competition.name}", title_style)
    elements.append(title)
    elements.append(Spacer(1, 20))
    
    # Competition info
    info_data = [
        ['Competition Name:', competition.name],
        ['Description:', competition.description or 'N/A'],
        ['Created:', competition.created_at.strftime('%Y-%m-%d %H:%M:%S')],
        ['Timer Duration:', f"{competition.timer_duration} seconds"],
        ['Report Generated:', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')]
    ]
    
    info_table = Table(info_data, colWidths=[2*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(info_table)
    elements.append(Spacer(1, 30))
    
    # Scores summary
    scores_title = Paragraph("Scores Summary", styles['Heading2'])
    elements.append(scores_title)
    elements.append(Spacer(1, 12))
    
    # Get all teams and their scores
    teams = Team.query.filter_by(competition_id=competition_id).all()
    
    if teams:
        # Header for scores table
        score_data = [['Team Name', 'Judge', 'Total Score', 'Submitted At']]
        
        for team in teams:
            scores = db.session.query(Score, User).join(
                User, Score.judge_id == User.id
            ).filter(
                Score.team_id == team.id,
                Score.is_submitted == True
            ).all()
            
            if scores:
                for score, judge in scores:
                    score_data.append([
                        team.team_name,
                        judge.full_name,
                        str(score.total_score),
                        score.submitted_at.strftime('%Y-%m-%d %H:%M:%S')
                    ])
            else:
                score_data.append([team.team_name, 'No scores yet', '-', '-'])
        
        scores_table = Table(score_data, colWidths=[2*inch, 2*inch, 1*inch, 2*inch])
        scores_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(scores_table)
    else:
        no_teams = Paragraph("No teams registered for this competition.", styles['Normal'])
        elements.append(no_teams)
    
    # Build PDF
    doc.build(elements)
    
    # Get PDF data
    pdf_data = buffer.getvalue()
    buffer.close()
    
    return pdf_data

def calculate_hash(data):
    """Calculate SHA-256 hash for data integrity"""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()
