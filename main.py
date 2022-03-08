from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from scanner import Scanner

main = Blueprint('main', __name__)
scanner = Scanner()

@main.route('/')
@login_required
def index():
    return render_template("index.html", current_user = current_user)

@main.route("/check", methods = ["POST"])
@login_required
def check_url():
  
  check_result = scanner.full_scan(request.form["url"])

  return render_template("index.html", check_result=check_result)

@main.route("/output", methods=["GET"])
@login_required
def output():
    with open("output_exploit_search.json",'r') as exploitResult:
        read = exploitResult.readlines()
        read = jsonify(read)
        
        return read