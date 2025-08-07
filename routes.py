import uuid
import hashlib
from datetime import datetime, timedelta
from flask import render_template, request, redirect, url_for, session, flash, jsonify, make_response
from werkzeug.security import generate_password_hash
from app import app, db
from models import (User, Competition, Question, ScoringLabel, Team,
                   JudgeAssignment, Score, QuestionScore, AuditLog)
from utils import require_login, require_role, log_user_action, generate_pdf_report

@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return redirect(url_for(f'{user.role}_dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if user and user.check_password(password):
            # Generate session token for single device login
            session_token = str(uuid.uuid4())
            user.session_token = session_token
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            session['user_id'] = str(user.id)
            session['username'] = user.username
            session['role'] = user.role
            session['session_token'] = session_token
            
            log_user_action(user.id, 'LOGIN', 'USER', user.id, 'User logged in')
            
            flash('Login successful!', 'success')
            return redirect(url_for(f'{user.role}_dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            user.session_token = None
            db.session.commit()
            log_user_action(user_id, 'LOGOUT', 'USER', user_id, 'User logged out')
    
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

# Admin Routes
@app.route('/admin/dashboard')
@require_login
@require_role('admin')
def admin_dashboard():
    user_count = User.query.count()
    competition_count = Competition.query.count()
    active_competitions = Competition.query.filter_by(is_active=True).count()
    
    recent_activities = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html', 
                         user_count=user_count,
                         competition_count=competition_count,
                         active_competitions=active_competitions,
                         recent_activities=recent_activities)

@app.route('/admin/users', methods=['GET', 'POST'])
@require_login
@require_role('admin')
def admin_users():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            role = request.form['role']
            full_name = request.form['full_name']
            
            # Check if user already exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'error')
            elif User.query.filter_by(email=email).first():
                flash('Email already exists', 'error')
            else:
                user = User()
                user.username = username
                user.email = email
                user.role = role
                user.full_name = full_name
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                
                log_user_action(session['user_id'], 'CREATE', 'USER', user.id, f'Created user {username}')
                flash('User created successfully', 'success')
        
        elif action == 'toggle_status':
            user_id = request.form['user_id']
            user = User.query.get(user_id)
            if user:
                user.is_active = not user.is_active
                db.session.commit()
                
                status = 'activated' if user.is_active else 'deactivated'
                log_user_action(session['user_id'], 'UPDATE', 'USER', user.id, f'User {status}')
                flash(f'User {status} successfully', 'success')
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/competitions', methods=['GET', 'POST'])
@require_login
@require_role('admin')
def admin_competitions():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create':
            name = request.form['name']
            description = request.form.get('description', '')
            timer_duration = int(request.form.get('timer_duration', 300))
            
            competition = Competition()
            competition.name = name
            competition.description = description
            competition.timer_duration = timer_duration
            competition.created_by = session['user_id']
            db.session.add(competition)
            db.session.commit()
            
            log_user_action(session['user_id'], 'CREATE', 'COMPETITION', competition.id, f'Created competition {name}')
            flash('Competition created successfully', 'success')
        
        elif action == 'toggle_status':
            competition_id = request.form['competition_id']
            competition = Competition.query.get(competition_id)
            if competition:
                competition.is_active = not competition.is_active
                db.session.commit()
                
                status = 'activated' if competition.is_active else 'deactivated'
                log_user_action(session['user_id'], 'UPDATE', 'COMPETITION', competition.id, f'Competition {status}')
                flash(f'Competition {status} successfully', 'success')
    
    competitions = Competition.query.all()
    return render_template('admin/competitions.html', competitions=competitions)

# Committee Routes
@app.route('/committee/dashboard')
@require_login
@require_role('committee')
def committee_dashboard():
    competitions = Competition.query.filter_by(is_active=True).all()
    judges = User.query.filter_by(role='judge', is_active=True).all()
    teams = Team.query.join(Competition).filter(Competition.is_active == True).all()
    
    return render_template('committee/dashboard.html',
                         competitions=competitions,
                         judges=judges,
                         teams=teams)

@app.route('/committee/assign_judges', methods=['GET', 'POST'])
@require_login
@require_role('committee')
def assign_judges():
    if request.method == 'POST':
        competition_id = request.form['competition_id']
        judge_id = request.form['judge_id']
        
        # Check if assignment already exists
        existing = JudgeAssignment.query.filter_by(
            competition_id=competition_id,
            judge_id=judge_id
        ).first()
        
        if existing:
            flash('Judge already assigned to this competition', 'error')
        else:
            assignment = JudgeAssignment()
            assignment.competition_id = competition_id
            assignment.judge_id = judge_id
            assignment.assigned_by = session['user_id']
            db.session.add(assignment)
            db.session.commit()
            
            log_user_action(session['user_id'], 'CREATE', 'JUDGE_ASSIGNMENT', assignment.id, 'Judge assigned to competition')
            flash('Judge assigned successfully', 'success')
    
    competitions = Competition.query.filter_by(is_active=True).all()
    judges = User.query.filter_by(role='judge', is_active=True).all()
    assignments = db.session.query(JudgeAssignment, User, Competition).join(
        User, JudgeAssignment.judge_id == User.id
    ).join(
        Competition, JudgeAssignment.competition_id == Competition.id
    ).all()
    
    return render_template('committee/assign_judges.html',
                         competitions=competitions,
                         judges=judges,
                         assignments=assignments)

@app.route('/committee/register_teams', methods=['GET', 'POST'])
@require_login
@require_role('committee')
def register_teams():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'register_team':
            competition_id = request.form['competition_id']
            team_name = request.form['team_name']
            school_name = request.form['school_name']
            
            team = Team()
            team.competition_id = competition_id
            team.team_name = team_name
            team.school_name = school_name
            db.session.add(team)
            db.session.commit()
            
            log_user_action(session['user_id'], 'CREATE', 'TEAM', team.id, f'Registered team {team_name} from {school_name}')
            flash('Tim berhasil didaftarkan', 'success')
        
        elif action == 'edit_team':
            team_id = request.form['team_id']
            team = Team.query.get_or_404(team_id)
            
            team.team_name = request.form['team_name']
            team.school_name = request.form['school_name']
            db.session.commit()
            
            log_user_action(session['user_id'], 'UPDATE', 'TEAM', team.id, f'Updated team {team.team_name} from {team.school_name}')
            flash('Tim berhasil diperbarui', 'success')
        
        elif action == 'delete_team':
            team_id = request.form['team_id']
            team = Team.query.get_or_404(team_id)
            
            db.session.delete(team)
            db.session.commit()
            
            log_user_action(session['user_id'], 'DELETE', 'TEAM', team_id, f'Deleted team {team.team_name} from {team.school_name}')
            flash('Tim berhasil dihapus', 'success')
    
    competitions = Competition.query.filter_by(is_active=True).all()
    teams = db.session.query(Team, Competition).join(
        Competition, Team.competition_id == Competition.id
    ).all()
    
    return render_template('committee/register_teams.html',
                         competitions=competitions,
                         teams=teams)

@app.route('/admin/questions/<competition_id>', methods=['GET', 'POST'])
@require_login
@require_role('admin')
def admin_manage_questions(competition_id):
    return manage_questions_logic(competition_id)

@app.route('/committee/questions/<competition_id>', methods=['GET', 'POST'])
@require_login
@require_role('committee')
def manage_questions(competition_id):
    return manage_questions_logic(competition_id)

def manage_questions_logic(competition_id):
    competition = Competition.query.get_or_404(competition_id)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_question':
            question_text = request.form['question_text']
            question_number = int(request.form['question_number'])
            
            question = Question()
            question.competition_id = competition_id
            question.question_text = question_text
            question.question_number = question_number
            db.session.add(question)
            db.session.flush()
            
            # Add dynamic scoring labels
            label_names = request.form.getlist('label_names[]')
            label_points = request.form.getlist('label_points[]')
            
            for label_name, points in zip(label_names, label_points):
                if label_name.strip() and points.strip():
                    scoring_label = ScoringLabel()
                    scoring_label.question_id = question.id
                    scoring_label.label = label_name.strip()
                    scoring_label.points = int(points)
                    db.session.add(scoring_label)
            
            db.session.commit()
            
            log_user_action(session['user_id'], 'CREATE', 'QUESTION', question.id, f'Added question to competition {competition.name}')
            flash('Question added successfully', 'success')
        
        elif action == 'edit_question':
            question_id = request.form['question_id']
            question = Question.query.get_or_404(question_id)
            
            question.question_text = request.form['question_text']
            question.question_number = int(request.form['question_number'])
            
            # Delete existing scoring labels
            ScoringLabel.query.filter_by(question_id=question_id).delete()
            
            # Add updated scoring labels
            label_names = request.form.getlist('label_names[]')
            label_points = request.form.getlist('label_points[]')
            
            for label_name, points in zip(label_names, label_points):
                if label_name.strip() and points.strip():
                    scoring_label = ScoringLabel()
                    scoring_label.question_id = question.id
                    scoring_label.label = label_name.strip()
                    scoring_label.points = int(points)
                    db.session.add(scoring_label)
            
            db.session.commit()
            
            log_user_action(session['user_id'], 'UPDATE', 'QUESTION', question.id, f'Updated question in competition {competition.name}')
            flash('Question updated successfully', 'success')
        
        elif action == 'delete_question':
            question_id = request.form['question_id']
            question = Question.query.get_or_404(question_id)
            
            # Delete associated scoring labels (cascade should handle this)
            db.session.delete(question)
            db.session.commit()
            
            log_user_action(session['user_id'], 'DELETE', 'QUESTION', question_id, f'Deleted question from competition {competition.name}')
            flash('Question deleted successfully', 'success')
    
    questions = Question.query.filter_by(competition_id=competition_id).order_by(Question.question_number).all()
    
    # Determine template based on user role
    template = 'admin/questions.html' if session.get('role') == 'admin' else 'committee/questions.html'
    return render_template(template, competition=competition, questions=questions)

# Judge Routes
@app.route('/judge/dashboard')
@require_login
@require_role('judge')
def judge_dashboard():
    # Get competitions assigned to this judge
    assignments = db.session.query(JudgeAssignment, Competition).join(
        Competition, JudgeAssignment.competition_id == Competition.id
    ).filter(
        JudgeAssignment.judge_id == session['user_id'],
        Competition.is_active == True
    ).all()
    
    # Get scoring progress
    scoring_progress = []
    for assignment, competition in assignments:
        teams = Team.query.filter_by(competition_id=competition.id).all()
        scored_teams = Score.query.filter_by(
            competition_id=competition.id,
            judge_id=session['user_id'],
            is_submitted=True
        ).count()
        
        scoring_progress.append({
            'competition': competition,
            'total_teams': len(teams),
            'scored_teams': scored_teams
        })
    
    return render_template('judge/dashboard.html',
                         assignments=assignments,
                         scoring_progress=scoring_progress)

@app.route('/judge/scoring/<competition_id>')
@require_login
@require_role('judge')
def judge_scoring(competition_id):
    # Verify judge is assigned to this competition
    assignment = JudgeAssignment.query.filter_by(
        competition_id=competition_id,
        judge_id=session['user_id']
    ).first_or_404()
    
    competition = Competition.query.get_or_404(competition_id)
    
    # Get teams not yet scored by this judge
    scored_team_ids = db.session.query(Score.team_id).filter_by(
        competition_id=competition_id,
        judge_id=session['user_id'],
        is_submitted=True
    )
    
    available_teams = Team.query.filter(
        Team.competition_id == competition_id,
        ~Team.id.in_(scored_team_ids.subquery().select())
    ).all()
    
    return render_template('judge/scoring.html',
                         competition=competition,
                         teams=available_teams)

@app.route('/judge/score_team/<team_id>', methods=['GET', 'POST'])
@require_login
@require_role('judge')
def score_team(team_id):
    team = Team.query.get_or_404(team_id)
    
    # Verify judge is assigned to this competition
    assignment = JudgeAssignment.query.filter_by(
        competition_id=team.competition_id,
        judge_id=session['user_id']
    ).first_or_404()
    
    # Check if already scored
    existing_score = Score.query.filter_by(
        team_id=team_id,
        judge_id=session['user_id'],
        is_submitted=True
    ).first()
    
    if existing_score:
        flash('You have already scored this team', 'error')
        return redirect(url_for('judge_scoring', competition_id=team.competition_id))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'start_timer':
            # Create or update score record with timer start
            score = Score.query.filter_by(
                team_id=team_id,
                judge_id=session['user_id'],
                is_submitted=False
            ).first()
            
            if not score:
                score = Score()
                score.competition_id = team.competition_id
                score.team_id = team_id
                score.judge_id = session['user_id']
                db.session.add(score)
            
            score.timer_started_at = datetime.utcnow()
            db.session.commit()
            
            log_user_action(session['user_id'], 'START_TIMER', 'SCORE', score.id, f'Started timer for team {team.team_name}')
            flash('Timer started! You can now score the team.', 'success')
        
        elif action == 'submit_score':
            score = Score.query.filter_by(
                team_id=team_id,
                judge_id=session['user_id'],
                is_submitted=False
            ).first()
            
            if not score or not score.timer_started_at:
                flash('Please start the timer first', 'error')
                return redirect(url_for('score_team', team_id=team_id))
            
            # Calculate total score and save question scores
            total_score = 0
            questions = Question.query.filter_by(competition_id=team.competition_id).order_by(Question.question_number).all()
            
            for question in questions:
                scoring_label_id = request.form.get(f'question_{question.id}')
                if scoring_label_id:
                    scoring_label = ScoringLabel.query.get(scoring_label_id)
                    if scoring_label:
                        question_score = QuestionScore()
                        question_score.score_id = score.id
                        question_score.question_id = question.id
                        question_score.scoring_label_id = scoring_label_id
                        question_score.points_awarded = scoring_label.points
                        db.session.add(question_score)
                        total_score += scoring_label.points
            
            # Save signatures
            score.judge_signature = request.form.get('judge_signature')
            score.participant_signature = request.form.get('participant_signature')
            score.total_score = total_score
            score.submitted_at = datetime.utcnow()
            score.is_submitted = True
            
            db.session.commit()
            
            log_user_action(session['user_id'], 'SUBMIT_SCORE', 'SCORE', score.id, f'Submitted score for team {team.team_name}')
            flash('Score submitted successfully!', 'success')
            return redirect(url_for('judge_scoring', competition_id=team.competition_id))
    
    # Get current score session
    current_score = Score.query.filter_by(
        team_id=team_id,
        judge_id=session['user_id'],
        is_submitted=False
    ).first()
    
    questions = Question.query.filter_by(competition_id=team.competition_id).order_by(Question.question_number).all()
    
    return render_template('judge/score_team.html',
                         team=team,
                         questions=questions,
                         current_score=current_score,
                         competition=team.competition)

# Participant Routes
@app.route('/participant/dashboard')
@require_login
@require_role('participant')
def participant_dashboard():
    # Get teams this participant belongs to
    team_participations = db.session.query(TeamParticipant, Team, Competition).join(
        Team, TeamParticipant.team_id == Team.id
    ).join(
        Competition, Team.competition_id == Competition.id
    ).filter(
        TeamParticipant.user_id == session['user_id']
    ).all()
    
    return render_template('participant/dashboard.html',
                         team_participations=team_participations)

@app.route('/participant/results/<team_id>')
@require_login
@require_role('participant')
def participant_results(team_id):
    team = Team.query.get_or_404(team_id)
    
    # Verify participant belongs to this team
    participation = TeamParticipant.query.filter_by(
        team_id=team_id,
        user_id=session['user_id']
    ).first_or_404()
    
    # Get all scores for this team
    scores = db.session.query(Score, User).join(
        User, Score.judge_id == User.id
    ).filter(
        Score.team_id == team_id,
        Score.is_submitted == True
    ).all()
    
    # Get detailed score breakdown
    score_details = []
    for score, judge in scores:
        question_scores = db.session.query(QuestionScore, Question, ScoringLabel).join(
            Question, QuestionScore.question_id == Question.id
        ).join(
            ScoringLabel, QuestionScore.scoring_label_id == ScoringLabel.id
        ).filter(
            QuestionScore.score_id == score.id
        ).order_by(Question.question_number).all()
        
        score_details.append({
            'score': score,
            'judge': judge,
            'question_scores': question_scores
        })
    
    return render_template('participant/results.html',
                         team=team,
                         score_details=score_details)

# API Routes for AJAX calls
@app.route('/api/timer_status/<score_id>')
@require_login
def timer_status(score_id):
    score = Score.query.get_or_404(score_id)
    
    # Verify user has access to this score
    if session['role'] == 'judge' and score.judge_id != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if score.timer_started_at:
        elapsed = (datetime.utcnow() - score.timer_started_at).total_seconds()
        competition = Competition.query.get(score.competition_id)
        if not competition:
            return jsonify({'error': 'Competition not found'}), 404
        
        timer_duration = competition.timer_duration
        remaining = max(0, timer_duration - elapsed)
        
        return jsonify({
            'started': True,
            'remaining': remaining,
            'expired': remaining <= 0
        })
    else:
        return jsonify({'started': False})

@app.route('/api/export_report/<competition_id>')
@require_login
@require_role(['admin', 'committee'])
def export_report(competition_id):
    competition = Competition.query.get_or_404(competition_id)
    
    # Generate PDF report
    pdf_data = generate_pdf_report(competition_id)
    
    response = make_response(pdf_data)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename={competition.name}_report.pdf'
    
    log_user_action(session['user_id'], 'EXPORT_REPORT', 'COMPETITION', competition.id, 'Exported competition report')
    
    return response
