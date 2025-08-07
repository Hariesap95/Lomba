# Competition Scoring System

## Overview

This is a web-based competition scoring system built with Flask and PostgreSQL that manages competitions, teams, judges, and scoring workflows. The system supports multiple user roles (admin, committee, judge, participant) with specific permissions and responsibilities. Key features include real-time timer management, digital signature collection, **configurable scoring systems with custom labels and point values**, comprehensive scoring mechanisms, question editing and deletion capabilities, and detailed result reporting with audit trails.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: Flask with Jinja2 templating
- **UI Framework**: Bootstrap 5 with dark theme for responsive design
- **JavaScript Components**: Custom timer functionality and digital signature capture using HTML5 Canvas
- **Styling**: Custom CSS for signature pads, timer displays, and enhanced user experience

### Backend Architecture
- **Web Framework**: Flask with SQLAlchemy ORM for database operations
- **Database Models**: Comprehensive relational model covering users, competitions, questions, teams, scores, and audit logs
- **Authentication System**: Session-based authentication with single device login enforcement using session tokens
- **Role-Based Access Control**: Decorator-based authorization system supporting four user roles
- **Password Security**: Werkzeug password hashing for secure credential storage

### Data Storage
- **Primary Database**: PostgreSQL with UUID primary keys for all entities
- **ORM**: SQLAlchemy with declarative base and relationship mapping
- **Session Management**: Flask sessions with CSRF protection enabled
- **Connection Pooling**: Configured with automatic reconnection and pool recycling

### Security Features
- **Authentication**: Username/password with hashed storage and session token validation
- **Authorization**: Role-based access control with route-level permission checks
- **Session Security**: Single device login enforcement and automatic session expiration
- **CSRF Protection**: Enabled WTF CSRF protection for form submissions
- **Audit Logging**: Comprehensive user action tracking for security and compliance

### Core Application Logic
- **Competition Management**: Full lifecycle management from creation to result generation
- **Configurable Scoring System**: Custom scoring labels with point values instead of fixed TL/KT/T/ST labels
- **Question Management**: Full CRUD operations for questions with edit and delete capabilities
- **Dynamic Label Creation**: Admin and committee can create unlimited custom scoring labels
- **Scoring Workflow**: Timer-based scoring sessions with digital signature capture using custom labels
- **Team Management**: Multi-member team registration and participant assignment
- **Judge Assignment**: Committee-managed judge allocation to competitions
- **Result Generation**: PDF report generation with detailed score breakdowns

## External Dependencies

### Core Framework Dependencies
- **Flask**: Web application framework with SQLAlchemy integration
- **PostgreSQL**: Primary database system for data persistence
- **Bootstrap 5**: Frontend UI framework with responsive design capabilities
- **Feather Icons**: Icon system for consistent visual elements

### Python Libraries
- **Werkzeug**: Security utilities for password hashing and proxy handling
- **ReportLab**: PDF generation library for creating detailed competition reports
- **WTForms**: Form handling and CSRF protection (implied by CSRF configuration)

### Frontend Libraries
- **HTML5 Canvas**: Digital signature capture functionality
- **JavaScript ES6**: Custom timer and signature pad implementations
- **Bootstrap JS**: Interactive UI components and responsive behavior

### Development and Deployment
- **Environment Configuration**: Environment variable-based configuration for database URLs and secrets
- **WSGI Deployment**: ProxyFix middleware for proper header handling in production
- **Debug Mode**: Configurable debug settings for development environments

### Database Schema
The system uses a comprehensive relational schema with entities for users, competitions, questions, scoring labels, teams, team participants, judge assignments, scores, question scores, and audit logs. All entities use UUID primary keys and include proper foreign key relationships with cascade delete operations where appropriate.