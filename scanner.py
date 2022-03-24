#!/usr/bin/python3
from Wappalyzer import Wappalyzer, WebPage
import requests
import vulners
import json
import os

class Scanner:
    def __init__(self, params):
        self.params = params

    def full_scan(self, url):
        return {
            "checked_url": url,
            "technology": self.scan_for_technologies(url),
            "vuln": self.scan_for_vuln(url),
            "server_version": self.scan_for_server_version(url),
            "request_tamp": self.request_tamp(url),
            "exploit_info": self.exploit_info(url),
            "mitigation_info": self.mitigation_info(url)
        }

    def scan_for_technologies(self, url):
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        res = wappalyzer.analyze_with_versions_and_categories(webpage)

        return res

    def scan_for_vuln(self, url):
        test1 = Scanner.test_xss(url)
        test2 = Scanner.test_ssti(url)
        test3 = Scanner.test_htmli(url)
        test4 = Scanner.test_sqli(url)
        test5 = Scanner.test_lfi(url)
        test6 = Scanner.test_cmdi(url)

        return f"{test1} , {test2} , {test3}, {test4}, {test5}, {test6}"

    def scan_for_server_version(self, url):
        req = requests.get(url)
        headers = req.headers
        server = headers['Server']

        return server

    def request_tamp(self, url):
        return "Soon To Be Updated"

    def exploit_info(self,url):
        req = requests.get(url)
        headers = req.headers

        server = headers["Server"]

        if server == '':
            return "No Server Version Found! Or Type!"
        else:
            VKey = self.params["v_key"] # get api key by going to https://vulners.com
            VApi = vulners.Vulners(api_key=VKey)

            search = VApi.searchExploit(server)
            search = json.dumps(search,indent=2)

            os.system(f"touch output_exploit_search.json")
            with open(f"output_exploit_search.json","w") as exploitResult:
                exploitResult.writelines(search)

            return f"Result Written To output_exploit_search.json, Access by visiting `/output`"

    def mitigation_info(self, url):
        payloadxss = "<script>document.write('xss');</script>"
        payloadssti = "{{7*7}}"
        payloadhtmli = "<h1>htmlinjection</h1>"

        reqxss = requests.get(f"{url}{payloadxss}",verify=False)
        reqssti = requests.get(f"{url}{payloadssti}",verify=False)
        reqhtmli = requests.get(f"{url}{payloadhtmli}",verify=False)

        if "xss" in reqxss.text and "49" in reqssti.text and "htmlinjection" in reqhtmli.text:
            return "SSTI,XSS, and HTMLinjection available can be prevented by reviewing the code and sanitizing the inputs"
        else:
            return "Check Through The Output"

    def test_ssti(url):
        payload = "{{7*7}}"
        fattempt = f"{url}{payload}"
        req = requests.get(fattempt,verify=False)
        #print(req.text)
        if req.status_code == 200:
            if "49" in req.text:
                return "SSTI(Server Side Template Injection)"
            else:
                return ""
        else:
            return ""

    def test_xss(url):
        fattempt = f"{url}<script>document.write('xss');</script>"
        req = requests.get(fattempt,verify=False)
        if req.status_code == 200:
            if "xss" in req.text:
                #print(req.text)
                return "XSS"
            else:
                return ""
        else:
            return ""

    def test_htmli(url):
        fattempt = f"{url}<h1 align='center' style='color:red;'>htmlinjection</h1>"
        req = requests.get(fattempt,verify=False)
        if req.status_code == 200:
            if "htmlinjection" in req.text:
                #print(req.text)
                return "HTML INJECTION"
            else:
                return ""
        else:
            return ""

    def test_sqli(url):
        payload = "' or 1=1 "
        fattempt = f"{url}{payload}"
        req = requests.get(fattempt,verify=False)
        if req.status_code == 200:
            if 'error' in req.text or 'SQL' in req.text or 'syntax' in req.text:
                #print(req.text)
                return "SQL INJECTION"
            else:
                return ""
        else:
            return ""
    """
    def test_lfi(url):
        payload1 = "../../../../../../../../../../../../etc/passwd"
        payload2 = "..//..//..//..//..//..//..//..//..//../etc/passwd"
        fattempt = f"{url}{payload1}"
        sattempt = f"{url}{payload2}"

        req1 = requests.get(fattempt)
        req2 = requests.get(sattempt)

        if req1.status_code == 200 and req2.status_code == 200:
            if "home/"in req1.text or "home/" in req2.status_code:
                return "LFI(Local File Inclusion)"
            else:
                return ""
        else:
            return ""
    """

    def test_cmdi(url):
        payload1 = "; echo 'aGVsbG8K'|base64 -d;"
        payload2 = "\necho 'aGVsbG8K'|base64 -d;"
        fattempt = f"{url}{payload1}"
        sattempt = f"{url}{payload2}"

        req1 = requests.get(fattempt,verify=False)
        req2 = requests.get(sattempt,verify=False)

        if req1.status_code == 200 and req2.status_code == 200:
            if 'hello' in req1.text or 'hello' in req2.text:
                return "OS Command Injection"
            else:
                return ""
        else:
            return ""

    def test_lfi(url):
        payload = "../../../../../../../../../../etc/passwd"
        fattempt = f"{url}{payload}"
        req = requests.get(fattempt,verify=False)
        #print(req.text)
        if req.status_code == 200:
            if 'root' in req.text:
                return "LFI(Local File Inclusion)"
            else:
                return ""
        else:
            if 'root:x:' in req.text:
                return "LFI(Local File Inclusion)"
            else:
                return ""
