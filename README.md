# bifröst

Intelligent Self-Learning Whitelist-based Web Application Firewall

THIS PROJECT IS IN EARLY DEVELOPMENT STAGE AND IS **NOT** READY FOR PRODUCTION.
IF YOU RUN THIS, EXPECT THE WORSE. IT'S STILL VERY UNTESTED AND DESPITE ALL 
EFFORTS MAY STILL CONTAIN MANY BUGS. **USE IT AT YOUR OWN RISK**

This WEB APPLICATION FIREWALL (WAF) uses its learning mode to gather a profile of the requested page. It analyzes and learns several parameters such as post fields, request/response content-size, response header count and size, file mimetypes and such to create a locked down whitelist to each page in each HTTP method provided.

Watch the [demo on YouTube](https://www.youtube.com/watch?v=qjzeJbAGgBo).

## How it works?
It analyzes the request and response headers and body, parses lots of things and compares to learnt data to check if the request or response is under conformity with the known behavior of these URLs.

Each anomaly detected adds up to the *threat score* (configurable) and when it reaches the threat threshold it will log and drop the connection immediately.

## Installation

* Checkout the repository
* Edit bifrost.conf (see below)
* Copy bifrost.db.orig to bifrost.db
* Edit your DNS/hosts entries
* Run ./bifrost.py 

*If you want to run in privileged ports (<1024) you'll need to run as root (sudo ./bifrost.py).*
**BIFRÖST DOES NOT DO PRIVILEGE DROP YET! BEWARE!!**

As an alternative, you might give [authbind](http://mutelight.org/authbind) a try.

## Configuration
### General section
This holds general configuration information for the WAF

* listen\_port, where bifröst should listen for requests (usually port 80)
* backend\_addr, IP address of your webserver
* backend\_port, where your webserver is listening for requests (usually port 80 [if in another host] or 8080)
* mode, bifröst mode (bypass, training, operational) [self explanatory]

### Analyzer
This section enables and configures the various analyzer settings.
The range comparators can be min/max range [range] or average [avg], plus tolerance.

* request\_content\_size, [range, avg] verifies the Request's content-size 
* response\_content\_size, [range, avg] verifies the Response's content-size 
* response\_header\_size, [range, avg] verifies the Response's header's size
* response\_header\_qty, [range, avg] verifies the Response's header's size
* request\_cookies, [0, 1] restrict Request cookies to known ones
* request\_headers, [0, 1] restrict Request headers to known ones
* response\_cookies, [0, 1] restrict Resposne cookies to known ones
* response\_headers, [0, 1] restrict Response headers to known ones
* request\_postdata, [0, 1] restrict POST fields to known ones
* upload\_filetype, [0, 1] restrict uploaded file's mime types to known ones

### Scorer
This section defines the score for each anomaly type. Defaults below. (Huge values are given to make a given anomaly to trigger a failure no matter what)

* request\_content\_size = 8
* response\_content\_size = 8
* response\_header\_size = 5
* response\_header\_qty = 5
* request\_cookies = 100
* request\_headers = 0
* response\_cookies = 100
* response\_headers = 100
* request\_postdata = 30
* upload\_filetype = 30

### Tolerance
Defines the tolerance margins for each range-evaluated parameter. 0 = No tolerance, 0.5 = 50% tolerance, 1 = 100% tolerance, and such. Defaults below.

* request\_content\_size = 0.05
* response\_content\_size = 0.2
* response\_header\_size = 0.2
* response\_header\_qty = 0.2

### Enforcer
Determines which score values will mark a request as a threat.

* response\_threshold = 15
* request\_threshold = 15

## Usage

Bifröst will be in the middle of your connection just like a reverse proxy would. Put it on training mode and it will start learning your pages' profiles then switch (in the configuration) to operational mode and give it a HUP signal.

All ready! (if not, train more!)

## Extra
To reload **bifröst** configuration without restarting just send a HUP signal to it.

    kill -s HUP $(ps aux | grep 'sudo ./bifrost.py' | grep -v grep | cut -d' ' -f6)

## @TODO

* drop root privileges
* add multi host support
* Add page-exception config support
* Add host-exception config support
* Use a better config file
* Check/enforce post-fields values averages
* Add RFC compliance check
* Drop connection more gracefully
* Add SSL support
* Fix multiple database calls (caching?)
* Make it all faster
* Kill all the remaining bugs :D (Specially all the @FIXMEs)
