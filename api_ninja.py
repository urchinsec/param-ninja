from flask import Flask, render_template, request
from flask_bootstrap import Bootstrap
from scanner import Scanner

scanner = Scanner()

app = Flask(__name__)
Bootstrap(app)

@app.route("/")
def index():
  return render_template("index.html")

@app.route("/check", methods = ["POST"])
def check_url():
  
  check_result = scanner.full_scan(request.form["url"])

  return render_template("index.html", check_result=check_result)