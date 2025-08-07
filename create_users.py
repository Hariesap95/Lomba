#!/usr/bin/env python3
"""
Script to create default users for the Competition Scoring System
"""

import os
import sys
from app import app, db
from models import User

def create_default_users():
    """Create default users for each role"""
    
    with app.app_context():
        # Check if admin already exists
        if User.query.filter_by(role='admin').first():
            print("Admin user already exists. Skipping user creation.")
            return
        
        # Default users data
        default_users = [
            {
                'username': 'admin',
                'email': 'admin@competition.local',
                'password': 'admin123',
                'role': 'admin',
                'full_name': 'System Administrator'
            },
            {
                'username': 'committee1',
                'email': 'committee1@competition.local',
                'password': 'committee123',
                'role': 'committee',
                'full_name': 'Committee Member 1'
            },
            {
                'username': 'judge1',
                'email': 'judge1@competition.local',
                'password': 'judge123',
                'role': 'judge',
                'full_name': 'Judge 1'
            },
            {
                'username': 'judge2',
                'email': 'judge2@competition.local',
                'password': 'judge123',
                'role': 'judge',
                'full_name': 'Judge 2'
            },
            {
                'username': 'participant1',
                'email': 'participant1@competition.local',
                'password': 'participant123',
                'role': 'participant',
                'full_name': 'Participant 1'
            },
            {
                'username': 'participant2',
                'email': 'participant2@competition.local',
                'password': 'participant123',
                'role': 'participant',
                'full_name': 'Participant 2'
            },
            {
                'username': 'participant3',
                'email': 'participant3@competition.local',
                'password': 'participant123',
                'role': 'participant',
                'full_name': 'Participant 3'
            }
        ]
        
        print("Creating default users...")
        
        for user_data in default_users:
            # Check if user already exists
            existing_user = User.query.filter_by(username=user_data['username']).first()
            if existing_user:
                print(f"User {user_data['username']} already exists. Skipping.")
                continue
            
            # Create new user
            user = User()
            user.username = user_data['username']
            user.email = user_data['email']
            user.role = user_data['role']
            user.full_name = user_data['full_name']
            user.set_password(user_data['password'])
            
            db.session.add(user)
            print(f"Created user: {user_data['username']} ({user_data['role']})")
        
        # Commit all changes
        db.session.commit()
        print("All users created successfully!")
        
        # Display login information
        print("\n" + "="*50)
        print("LOGIN CREDENTIALS")
        print("="*50)
        print("Admin:")
        print("  Username: admin")
        print("  Password: admin123")
        print()
        print("Committee:")
        print("  Username: committee1")
        print("  Password: committee123")
        print()
        print("Judges:")
        print("  Username: judge1 / judge2")
        print("  Password: judge123")
        print()
        print("Participants:")
        print("  Username: participant1 / participant2 / participant3")
        print("  Password: participant123")
        print("="*50)

if __name__ == '__main__':
    create_default_users()