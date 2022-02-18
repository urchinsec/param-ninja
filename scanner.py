#!/usr/bin/python3
from Wappalyzer import Wappalyzer, WebPage
import requests
import json

class Scanner:
    def full_scan(self, url):
        return {
            "checked_url": url,
            "technology": self.scan_for_technologies(url),
            "vuln": self.scan_for_vuln(url),
            "server_version": self.scan_for_server_version(url)
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
        return "Server 2009"
        # about to work on this and add some more.

    def test_ssti(url):
        payload = "{{7*7}}"
        fattempt = f"{url}{payload}"
        req = requests.get(fattempt)
        print(req.text)
        if "49" in req.text:
            return "SSTI(Server Side Template Injection)"
        else:
            return ""

    def test_xss(url):
        fattempt = f"{url}<script>document.write('xss');</script>"
        req = requests.get(fattempt)
        if "xss" in req.text:
            return "XSS(Reflective)"
        else:
            return ""

    def test_htmli(url):
        fattempt = f"{url}<h1 align='center' style='color:red;'>htmlinjection</h1>"
        req = requests.get(fattempt)
        if "htmlinjection" in req.text:
            return "HTML INJECTION"
        else:
            return ""
