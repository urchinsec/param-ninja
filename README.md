[<img src="param-ninja-logo.png" width="150"/>](param-ninja-logo.png)
An automated penetration testing tool , that automates web vulnerabilities testing upon a URL given with a parameter

## INSTALLATION
#### Requirements::
```
pip3 install -r requirements.txt
```
This should install all the requirements required to fully function.

#### Configuration::
You need to create a `config` file and put in your secret key and SQLAlchemy URL as an example:

```
SECRET_KEY = 'somesecretgoesherepewpew333'
SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite'
VULN_KEY = 'keyhere'
SHODAN_API_KEY = 'keyhere'
WHOISXMLAPI_KEY = 'keyhere'
```

You can generate your Shodan API from shodan's official website , and vulners from https://vulners.com , whoisxmlapi from https://whoisxmlapi.com

## USAGE
Now to finally run it up :

```
python3 starter.py
```

And the it will start the flask web server , then you can access it from the web by visiting `http://localhost:5000/`
then you will need to log in , where the default creds `admin:admin`:

![Login](https://user-images.githubusercontent.com/49201347/157664209-bb7bca34-5a4b-47f9-b728-7745f768e12f.png)


Now in the main page you can put in a URL with an endpoint that you want to test , and then click on scan and it'll perform the magic.

![Main](https://user-images.githubusercontent.com/49201347/157664486-271294ec-d4a5-4407-a878-14485288ed44.png)

Then the user can change the password by navigating to the profile tab , and setting the username he wants as well as the password.

![ChangePassword](https://user-images.githubusercontent.com/49201347/157664833-cb27f52e-db8a-44f0-9c14-d861b0a234fc.png)

This is an example of scanning `https://api.github.com/users` but it's  best you put something with an endpoint and parameter , since this is a parameter tester :) , As seen below are the output:

![Scanned](https://user-images.githubusercontent.com/49201347/157249666-b6e0add1-ef2f-4f2e-ba9f-c9b55e862ee7.png)

Another Example:

![image](https://user-images.githubusercontent.com/49201347/189547596-5b8a22d0-6d89-4374-aab9-b6048eaff54e.png)


**We have a new tab which is `Post Based`, and it's underdevelopment.**

## WHAT'S MORE?
You can visit `/output` to check the output of possible exploits found from exploit-db.
You can visit `/subdomains` to check the output of subdomains available under the domain provided at first.
You can visit `/domain` to get information about the domain hosting the web application.

**FUNCTIONALITIES::**

Below are the vulnerabilities that can be tested currently:

1. XSS (Cross Site Scripting)
2. HTML injection
3. SSTI (Server Side Template Injection)
4. OS Command Injection
5. LFI (Local File Inclusion)
6. SQL injection
7. SSRF (Server Side Request Forgery)
8. Directory Traversal
9. Open Redirection
10. Anonymous FTP Login (if exists an FTP Service)

More Vulnerability testing functions will be added soon:)

The tool performs 10 core functions as of now, and these are:

1. Determine Technologies Used
2. Find Vulnerabilities
3. Check Web Server Type
4. Get Domain Information
5. Perform Ports Enumeration
6. Pull DNS Records
7. Get Suspicious Directories
8. Perform Subdomain Enumeration
9. Provide Exploit Information Upon Technologies Used
10. Provide Mitigation Information Accordingly To The Exploits

## CONTACTS::
1. info@urchinsec.com
2. [urchinsec](https://twitter.com/urchinsec_)

*LOGO ArtWork By [witchdocsec](https://github.com/witchdocsec/)*
