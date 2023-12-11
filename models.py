from flask_login import UserMixin
from starter import db


class User(UserMixin, db.Model):
    __tablename__ = "param_ninja_users"
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    username = db.Column(db.String(100))

    def __init__(self, email, password, username):
        self.email = email
        self.password = password
        self.username = username


class ScanLog(db.Model):
    __tablename__ = "param_ninja_scans"
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(80))
    username = db.Column(db.String())
    scan_output = db.Column(db.String())
    output_file = db.Column(db.String())
    time_scan = db.Column(db.String())

    def __init__(self, domain, username, scan_output, output_file, time_scan):
        self.domain = domain
        self.username = username
        self.scan_output = scan_output
        self.output_file = output_file
        self.time_scan = time_scan


class ReportLog(db.Model):
    __tablename__ = "param_ninja_reports"
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String())
    username = db.Column(db.String())
    report_path = db.Column(db.String())
    report_time = db.Column(db.String())

    def __init__(self, domain, username, report_path):
        self.domain = domain
        self.username = username
        self.report_path = report_path
