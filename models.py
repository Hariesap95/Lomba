import uuid
from datetime import datetime
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.dialects.postgresql import UUID

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, committee, judge, participant
    full_name = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    session_token = db.Column(db.String(256))  # For single device login
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Competition(db.Model):
    __tablename__ = 'competitions'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    timer_duration = db.Column(db.Integer, default=300)  # Timer in seconds
    
    questions = db.relationship('Question', backref='competition', lazy=True, cascade='all, delete-orphan')
    judge_assignments = db.relationship('JudgeAssignment', backref='competition', lazy=True, cascade='all, delete-orphan')
    teams = db.relationship('Team', backref='competition', lazy=True, cascade='all, delete-orphan')

class Question(db.Model):
    __tablename__ = 'questions'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    competition_id = db.Column(UUID(as_uuid=True), db.ForeignKey('competitions.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    question_number = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    scoring_labels = db.relationship('ScoringLabel', backref='question', lazy=True, cascade='all, delete-orphan')

class ScoringLabel(db.Model):
    __tablename__ = 'scoring_labels'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    question_id = db.Column(UUID(as_uuid=True), db.ForeignKey('questions.id'), nullable=False)
    label = db.Column(db.String(10), nullable=False)  # TL, KT, T, ST
    points = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Team(db.Model):
    __tablename__ = 'teams'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    competition_id = db.Column(UUID(as_uuid=True), db.ForeignKey('competitions.id'), nullable=False)
    team_name = db.Column(db.String(200), nullable=False)  # Custom team name
    school_name = db.Column(db.String(200), nullable=False)  # School name
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    scores = db.relationship('Score', backref='team', lazy=True, cascade='all, delete-orphan')



class JudgeAssignment(db.Model):
    __tablename__ = 'judge_assignments'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    competition_id = db.Column(UUID(as_uuid=True), db.ForeignKey('competitions.id'), nullable=False)
    judge_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    assigned_by = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)

class Score(db.Model):
    __tablename__ = 'scores'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    competition_id = db.Column(UUID(as_uuid=True), db.ForeignKey('competitions.id'), nullable=False)
    team_id = db.Column(UUID(as_uuid=True), db.ForeignKey('teams.id'), nullable=False)
    judge_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    judge_signature = db.Column(db.Text)  # Base64 encoded signature
    participant_signature = db.Column(db.Text)  # Base64 encoded signature
    total_score = db.Column(db.Integer, default=0)
    submitted_at = db.Column(db.DateTime)
    timer_started_at = db.Column(db.DateTime)
    is_submitted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    question_scores = db.relationship('QuestionScore', backref='score', lazy=True, cascade='all, delete-orphan')

class QuestionScore(db.Model):
    __tablename__ = 'question_scores'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    score_id = db.Column(UUID(as_uuid=True), db.ForeignKey('scores.id'), nullable=False)
    question_id = db.Column(UUID(as_uuid=True), db.ForeignKey('questions.id'), nullable=False)
    scoring_label_id = db.Column(UUID(as_uuid=True), db.ForeignKey('scoring_labels.id'), nullable=False)
    points_awarded = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(UUID(as_uuid=True))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
