from flask import Flask, render_template, request, jsonify
from flask_bootstrap import Bootstrap
from scanner import Scanner

import json

scanner = Scanner()

app = Flask(__name__)
Bootstrap(app)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check_url():
    check_result = scanner.full_scan(request.form["url"])
    return render_template("index.html", check_result=check_result)

@app.route("/output", methods=["GET"])
def output():
    with open("output_exploit_search.json",'r') as exploitResult:
        read = exploitResult.readlines()
        read = jsonify(read)
        
        return read

if __name__ == "__main__":
    app.run()
