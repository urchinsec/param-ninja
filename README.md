# PARAM-NINJA
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
```

Visit https://vulners.com/ and generate an API key and then add it in the config also:

```
SECRET_KEY = 'somesecretgoesherepewpew333'
SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite'
VULN_KEY = 'keyhere'
```

## USAGE
Now to finally run it up :

```
python3 starter.py
```

And the it will start the flask web server , then you can access it from the web by visiting `http://localhost:5000/`
then you will need to log in , where the default creds `admin:admin`:

![Login_Param_Ninja](https://user-images.githubusercontent.com/49201347/157232948-2703c2ff-94b6-403a-ab45-d622bf4d2238.png)

Now in the main page you can put in a URL with an endpoint that you want to test , and then click on scan and it'll perform the magic.

![Main_Param_Ninja](https://user-images.githubusercontent.com/49201347/157233470-860bd9bc-173e-40d4-b498-dd801acac8a0.png)

This is an example of scanning `https://api.github.com/users` but it's  best you put something with an endpoint and parameter , since this is a parameter tester :) , As seen below are the output:

![Scanned](https://user-images.githubusercontent.com/49201347/157249666-b6e0add1-ef2f-4f2e-ba9f-c9b55e862ee7.png)

## WHAT'S MORE?
You can visit `/output` to check the output of possible exploits found from exploit-db.

**FUNCTIONALITIES::**

Below are the vulnerabilities that can be tested currently:

1. XSS (Cross Site Scripting)
2. HTML injection
3. SSTI (Server Side Template Injection)
4. OS Command Injection
5. LFI (Local File Inclusion)
6. SQL injection

More Vulnerability testing functions will be added soon:)

## CONTACTS::
1. urchinsec@protonmail.com
2. https://discord.gg/red66VCSEp
3. tahacodez@gmail.com
4. bug.fetcher@gmail.com
5. [tahaafarooq](https://twitter.com/tahaafarooq)
