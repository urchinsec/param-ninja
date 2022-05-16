import os
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from scanner import Scanner, PostScanner


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

    @main.route("/posttool", methods=["GET"])
    @login_required
    def posttool():
        return render_template("post.html")

    # to work on function!
    @main.route("/post", methods=["POST"])
    @login_required
    def post_url():
        post_result = PostScanner.full_test(request.form["url"], request.form["data"])

        return render_template("post.html", post_result=post_result)

    @main.route("/check", methods=["POST"])
    @login_required
    def check_url():
        check_result = scanner.full_scan(request.form["url"])

        return render_template("index.html", check_result=check_result)

    @main.route("/output", methods=["GET"])
    @login_required
    def output():
        with open("output_exploit_search.json", 'r') as exploitResult:
            read = exploitResult.readlines()
            read = jsonify(read)

            return read

    @main.route("/suspicious", methods=["GET"])
    @login_required
    def suspicious_files():
        with open("found_files.txt", "r") as found:
            read = found.readlines()

            return read

    @main.route("/domain", methods=["GET"])
    @login_required
    def domain():
        with open("output_domain_info.json", "r") as domainInfo:
            read = domainInfo.readlines()
            read = jsonify(read)

            return read

    @main.route("/lfi", methods=["GET"])
    @login_required
    def lfi_results():
        with open("lfi_proof.html", "r") as lfi_proof:
            read = lfi_proof.readlines()
            
        os.system('mv lfi_proof.html templates/lfi_proof.html')
        return render_template('lfi_proof.html')

    @main.route("/oscmdi", methods=["GET"])
    @login_required
    def oscmdi_results():
        with open("os_cmdi_proof.html", "r") as oscmdi_proof:
            read = oscmdi_proof.readlines()

            return read


    @main.route("/subdomains",methods=["GET"])
    @login_required
    def subdomains():
        with open("subdomains.txt","r") as subdomains:
            read = subdomains.readlines()
            read = jsonify(read)

            return read

    @main.route("/dnsrecords", methods=["GET"])
    @login_required
    def dnsrecords():
        with open("dnsrecord.json", "r") as dnsrecords:
            read = dnsrecords.readlines()
            read = jsonify(read)

            return read

    return (main)
