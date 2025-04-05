from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import validates
from sqlalchemy import Enum
from flask_login import UserMixin
import uuid

db = SQLAlchemy()

# Define status and severity as string literals for SQLAlchemy Enum
VULNERABILITY_STATUSES = ('open', 'in-progress', 'resolved', 'closed', 'reopened')
SEVERITY_LEVELS = ('critical', 'high', 'medium', 'low', 'info')
USER_ROLES = ('admin', 'analyst', 'viewer')
SCAN_STATUSES = ('pending', 'in_progress', 'completed', 'failed')

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(Enum(*USER_ROLES, name='user_role'), default='analyst', nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.Index('idx_user_email', 'email'),
        db.Index('idx_user_role', 'role'),
    )

    @validates('role')
    def validate_role(self, key, role):
        if role not in USER_ROLES:
            raise ValueError(f"Invalid role. Must be one of: {USER_ROLES}")
        return role

    def __repr__(self):
        return f'<User {self.email}>'

class ScanResult(db.Model):
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    target_domain = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    status = db.Column(Enum(*SCAN_STATUSES, name='scan_status'), default='pending')
    progress = db.Column(db.Integer, default=0)
    current_tool = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')
    details = db.relationship('ScanDetail', backref='scan', lazy=True, cascade='all, delete-orphan')

    # Indexes for better query performance
    __table_args__ = (
        db.Index('idx_scan_target_domain', 'target_domain'),
        db.Index('idx_scan_status', 'status'),
        db.Index('idx_scan_id', 'scan_id'),
    )

    @validates('status')
    def validate_status(self, key, status):
        if status not in SCAN_STATUSES:
            raise ValueError(f"Invalid status. Must be one of: {SCAN_STATUSES}")
        return status

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_results.id'), nullable=False)
    vulnerability_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(Enum(*SEVERITY_LEVELS, name='severity_level'), nullable=False)
    status = db.Column(Enum(*VULNERABILITY_STATUSES, name='vulnerability_status'), default='open')
    description = db.Column(db.Text)
    affected_component = db.Column(db.String(255))
    remediation_steps = db.Column(JSONB)
    cvss_score = db.Column(db.Float)
    cve_ids = db.Column(JSONB)  # Store multiple CVE IDs if applicable
    proof_of_concept = db.Column(db.Text)  # Store PoC or evidence
    technical_details = db.Column(JSONB)  # Store detailed technical information
    assigned_to = db.Column(db.String(100))  # For tracking assignment
    resolution_notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    comments = db.relationship('VulnerabilityComment', backref='vulnerability', lazy=True, cascade='all, delete-orphan')

    # Indexes
    __table_args__ = (
        db.Index('idx_vuln_severity', 'severity'),
        db.Index('idx_vuln_status', 'status'),
        db.Index('idx_vuln_scan_id', 'scan_id'),
    )

    @validates('severity')
    def validate_severity(self, key, severity):
        if severity not in SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity level. Must be one of: {SEVERITY_LEVELS}")
        return severity

    @validates('status')
    def validate_status(self, key, status):
        if status not in VULNERABILITY_STATUSES:
            raise ValueError(f"Invalid status. Must be one of: {VULNERABILITY_STATUSES}")
        return status

class VulnerabilityComment(db.Model):
    __tablename__ = 'vulnerability_comments'

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.Index('idx_comment_vuln_id', 'vulnerability_id'),
    )

class ScanDetail(db.Model):
    __tablename__ = 'scan_details'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_results.id'), nullable=False)
    tool_name = db.Column(db.String(100), nullable=False)
    raw_output = db.Column(db.Text)
    configuration = db.Column(JSONB)
    error_logs = db.Column(db.Text)  # Store any errors encountered during scanning
    performance_metrics = db.Column(JSONB)  # Store scanning performance data
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.Index('idx_detail_scan_id', 'scan_id'),
        db.Index('idx_detail_tool', 'tool_name'),
    )