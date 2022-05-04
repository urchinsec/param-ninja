from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from scanner import Scanner

def build_main_blueprint(app):

    main = Blueprint('main', __name__)
    scanner_config = {
        "v_key": app.config['VULN_KEY'],
        "s_key": app.config['SHODAN_API_KEY'],
        'w_key': app.config['WHOISXMLAPI_KEY']
    }
    scanner = Scanner(scanner_config)

    @main.route('/')
    @login_required
    def index():
        return render_template("index.html")

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

    @main.route("/domain",methods=["GET"])
    @login_required
    def domain():
        with open("output_domain_info.json","r") as domainInfo:
            read = domainInfo.readlines()
            read = jsonify(read)

            return read

    @main.route("/subdomains",methods=["GET"])
    @login_required
    def subdomains():
        with open("sbdomains.json","r") as subdomains:
            read = subdomains.readlines()
            read = jsonify(read)

            return read

    @main.route("/dnsrecords",methods=["GET"])
    @login_required
    def dnsrecords():
        with open("dnsrecord.json","r") as dnsrecords:
            read = dnsrecords.readlines()
            read = jsonify(read)

            return read
    
    return (main)
