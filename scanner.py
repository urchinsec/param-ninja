#!/usr/bin/python3
from Wappalyzer import Wappalyzer, WebPage
import requests
import vulners
import json
import os

class Scanner:
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

        return f"{test1} , {test2} , {test3}"
  
    def scan_for_server_version(self, url):
        req = requests.get(url)
        headers = req.headers
        server = headers['Server']

        return server

    def request_tamp(self, url):
        return "Not Spotted"

    def exploit_info(self,url):
        req = requests.get(url)
        headers = req.headers
        server = headers["Server"]
        
        VKey = "AE4E6ISN5JIV4EX0E0MGJRFXLKAQ3BNNP8W20L3IFHT7EOZXD5ZPI5P4QOCP5YP2"
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
        
        reqxss = requests.get(f"{url}{payloadxss}")
        reqssti = requests.get(f"{url}{payloadssti}")
        reqhtmli = requests.get(f"{url}{payloadhtmli}")

        if "xss" in reqxss.text and "49" in reqssti.text and "htmlinjection" in reqhtmli.text:
            return "SSTI,XSS, and HTMLinjection available can be prevented by reviewing the code and sanitizing the inputs"
        else:
            return "Check Through The Output"

    def test_ssti(url):
        payload = "{{7*7}}"
        fattempt = f"{url}{payload}"
        req = requests.get(fattempt)
        print(req.text)
        if req.status_code == 200:
            if "49" in req.text:
                return "SSTI(Server Side Template Injection)"
            else:
                return ""
        else:
            return ""

    def test_xss(url):
        fattempt = f"{url}<script>document.write('xss');</script>"
        req = requests.get(fattempt)
        if req.status_code == 200:
            if "xss" in req.text:
                print(req.text)
                return "XSS(Reflective)"
            else:
                return ""
        else:
            return ""

    def test_htmli(url):
        fattempt = f"{url}<h1 align='center' style='color:red;'>htmlinjection</h1>"
        req = requests.get(fattempt)
        if req.status_code == 200:
            if "htmlinjection" in req.text:
                print(req.text)
                return "HTML INJECTION"
            else:
                return ""
        else:
            return ""
