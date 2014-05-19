#!/usr/bin/env python

#
#  88          88    ad88               88 88                       
#  88          ""   d8"                 "" ""                ,d     
#  88               88                                       88     
#  88,dPPYba,  88 MM88MMM 8b,dPPYba,  ,adPPYba,  ,adPPYba, MM88MMM  
#  88P'    "8a 88   88    88P'   "Y8 a8"     "8a I8[    ""   88     
#  88       d8 88   88    88         8b       d8  `"Y8ba,    88     
#  88b,   ,a8" 88   88    88         "8a,   ,a8" aa    ]8I   88,    
#  8Y"Ybbd8"'  88   88    88          `"YbbdP"'  `"YbbdP"'   "Y888  
#
#  INTELLIGENT WEB APPLICATION FIREWALL
#  by: Jan Seidl
#
#  THIS IS PRE-ALPHA SOFTWARE
#  IT'S BUGGY, FALSE-POSITIVE-Y AND SUCH
#  DO *NOT* USE THIS IN PRODUCTION
#  - I repeat -
#  DO ->*NOT*<- USE THIS IN PRODUCTION
#

# Global WAF instance
waf = None

#######################################
# Constants
#######################################

CONFIG_FILE = 'bifrost.conf'
DATABASE_FILE = 'bifrost.db'

MODE_TRAINING = 1
MODE_OPERATIONAL = 2
MODE_BYPASS = 3

ACTION_DROP = 1
ACTION_PASS = 2

CHUNK_END = '0\r\n\r\n'

#######################################
# Imports
#######################################

import ConfigParser, magic, Cookie
import sys, pprint, sqlite3, signal, textwrap
from twisted.internet import protocol, reactor
from BaseHTTPServer import BaseHTTPRequestHandler
import cgi
from httplib import HTTPResponse as HTTPR
from StringIO import StringIO
from twisted.python import log

#######################################
# Util functions
#######################################

def in_range(minval, maxval, value, tolerance):
    tolerance = float(tolerance)
    maxval = int(maxval)
    minval = int(minval)
    maxval += (maxval*tolerance)
    minval += (minval*tolerance)
    return (minval <= value <= maxval)

def in_average(mean, value, tolerance):

    threshold = (mean*tolerance)
    maxval = (mean+threshold)
    minval = (mean-threshold)
    return in_range(minval, maxval, value, 0)

# http://stackoverflow.com/questions/287871/print-in-terminal-with-colors-using-python 
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# http://pythonwise.blogspot.com.br/2010/02/parse-http-response.html
class FakeSocket(StringIO):
    def makefile(self, *args, **kw):
        return self

#######################################
# HTTP Request and Response Classes
#######################################

# http://stackoverflow.com/questions/2115410/does-python-have-a-module-for-parsing-http-requests-and-responses
class HTTPRequest(BaseHTTPRequestHandler):

    form = {}

    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

        if self.command == 'POST':
            # Parse the form data posted
            self.form = cgi.FieldStorage(
                    fp=self.rfile, 
                    headers=self.headers,
                    environ={'REQUEST_METHOD':'POST',
                    'CONTENT_TYPE':self.headers['Content-Type'],
                    })

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

class HTTPResponse():

    headers = {}
    fp = None
    length = None
    chunked = None

    def __init__(self, response_text):
        self.fp = FakeSocket(response_text)
        res = HTTPR(self.fp)
        res.begin()

        headers = res.getheaders()
        for header in headers:
            self.headers[header[0]] = header[1]

        self.length = res.getheader('Content-Length')
        self.chunked = res.getheader('Transfer-Encoding')
 
#######################################
# Endpoints
# Adapted from http://www.mostthingsweb.com/2013/08/a-basic-man-in-the-middle-proxy-with-twisted/
# Adapted from http://stackoverflow.com/a/15645169/221061
#######################################

##
# ServerProtocol = Client -> WAF | WAF -> Client
##
class ServerProtocol(protocol.Protocol):

    def __init__(self):
        self.buffer = None
        self.client = None
 
    def connectionMade(self):
        factory = protocol.ClientFactory()
        factory.protocol = ClientProtocol
        factory.server = self
 
        reactor.connectTCP(waf.server_addr, waf.server_port, factory)
 
    def drop_connection(self):
        # FIX ME -- NEED TO CLOSE THIS BOTH ENDS
        print bcolors.FAIL + "Dropping connection." + bcolors.ENDC
        self.transport.loseWriteConnection()
        self.transport.loseConnection()
        self.transport.abortConnection()

    # Client => Proxy
    def dataReceived(self, data):

        if self.client:
            self.client.write(data)
        else:
            self.buffer = data

    # Proxy => Client
    def write(self, data):
        self.transport.write(data)
 
##
# ClientProtocol = Server -> WAF | WAF -> Server
##
class ClientProtocol(protocol.Protocol):

    client_request = None
    response_buffer = None
    request_buffer = None
    chunked = False

    request_size = 0

    def connectionMade(self):
        self.factory.server.client = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''

    def valid_files(self, post):
        mimes = []
        # Get uploaded files' mime
        for field in post.keys():
            if post[field].filename:
                file_data = post[field].file.read()
                mime = waf.magic.buffer(file_data)
                mimes.append(mime)

        dataset = self.fetch_set('uploads', 'mimetype', None, path_only = True)
        for mime in set(mimes):
            if mime is dataset:
                print bcolors.WARNING + "[ANOMALY] File mimetype '%s' not allowed on requests for this URL ('%s')." % (mime, self.client_request.path) + bcolors.ENDC
                return False

        return True


    def valid_post(self, post_keys, r_type):

        dataset = self.fetch_set('postdata', 'field', None, path_only = True)
        for post in post_keys:
            post_name = post.strip().lower()
            if post_name not in dataset:
                print bcolors.WARNING + "[ANOMALY] POST field '%s' not allowed on %s for this URL ('%s')." % (post_name, 'requests' if r_type == 'req' else 'responses', self.client_request.path) + bcolors.ENDC
                return False

        return True


    def valid_headers(self, header_keys, r_type):

        dataset = self.fetch_set('headers', 'header', r_type)
        for header in header_keys:
            header_name = header.strip().lower()
            if header_name not in dataset:
                print bcolors.WARNING + "[ANOMALY] Header '%s' not allowed on %s for this URL/method ('%s','%s')." % (header_name, 'requests' if r_type == 'req' else 'responses', self.client_request.command, self.client_request.path) + bcolors.ENDC
                return False

        return True

    def valid_cookies(self, cookie_str, r_type):

        ck = Cookie.SimpleCookie()
        ck.load(cookie_str)
        dataset = self.fetch_set('cookies', 'cookie', r_type)
        for cookie in ck.keys():
            cookie_name = cookie.strip().lower()
            if cookie_name not in dataset:
                print bcolors.WARNING + "[ANOMALY] Cookie '%s' not allowed on %s for this URL/method ('%s','%s')." % (cookie_name, 'requests' if r_type == 'req' else 'responses', self.client_request.command, self.client_request.path) + bcolors.ENDC
                return False

        return True
    def fetch_set(self, table, field, r_type, path_only=False):

        items = []
        if path_only:
            cursor = waf.cursor.execute("SELECT %s FROM %s WHERE path = ?" % (field, table), (self.client_request.path,))
        else:
            cursor = waf.cursor.execute("SELECT %s FROM %s WHERE path = ? and method = ? AND type = ?" % (field, table), (self.client_request.path, self.client_request.command, r_type))
        for row in cursor:
            items.append(row[0])

        return set(items)

    def fetch_averages(self, path, r_type):

        # Get averages
        query = "SELECT MIN(headers_qty) as min_hqty, \
                        MAX(headers_qty) as max_hqty, \
                        AVG(headers_qty) as hqty, \
                        MIN(headers_size) as mix_hsize, \
                        MAX(headers_size) as max_hsize, \
                        AVG(headers_size) as hsize, \
                        MIN(content_size) as min_csize, \
                        MAX(content_size) as max_csize, \
                        AVG(content_size) as csize \
                        FROM urls WHERE path = ? AND type = ?"
        waf.cursor.execute(query, (path,r_type))
        return waf.cursor.fetchone()

    def analyzeRequest(self):

        score = 0
        request = self.client_request
        command = request.command
        path = request.path

        # Check if page can be acessed within given method
        waf.cursor.execute("SELECT method FROM urls WHERE path = ? AND method = ? AND type = 'req' GROUP BY METHOD", (path, command) );
        methods = waf.cursor.fetchone()

        if methods is None:
            print bcolors.FAIL + "[ANOMALY] URL/method ('%s','%s') not in database." % (command, path) + bcolors.ENDC
            if waf.unknown_urls_action == ACTION_PASS:
                return True
            else:
                self.request_buffer = None
                return False

        averages = self.fetch_averages(path, 'req')

        # Content SIZE
        avgs = averages[6:9]
        ret = True
        header_size = len(str(request.headers))
        content_size = (len(self.request_buffer)-header_size)
        tolerance = waf.config.get('tolerance', 'response_content_size')
        if waf.config.get('analyzer', 'response_content_size') == 'avg':
            ret = in_average(avgs[2], content_size, tolerance)
        else:
            ret = in_range(avgs[0], avgs[1], content_size, tolerance)
        if not ret:
            print bcolors.WARNING + "[ANOMALY] URL '%s' has an unexpected request content size (%d)." % (path, content_size) + bcolors.ENDC
            score += waf.config.getint('scorer', 'request_content_size')

        # Check for valid cookies
        if waf.config.getint('analyzer', 'request_cookies') == 1 and 'Cookie' in request.headers:
            if not self.valid_cookies(request.headers['Cookie'], 'req'):
                score += waf.config.getint('scorer', 'request_cookies')

        # Header sanity
        if waf.config.getint('analyzer', 'request_headers') == 1:
            if not self.valid_headers(request.headers.keys(), 'req'):
                score += waf.config.getint('scorer', 'request_headers')

        # POST sanity
        if command == 'POST' and  waf.config.getint('analyzer', 'request_postdata') == 1:
            if not self.valid_post(request.form.keys(), 'req'):
                score += waf.config.getint('scorer', 'request_postdata')

        # Uploaded File MIME type sanity
        if command == 'POST' and  waf.config.getint('analyzer', 'upload_filetype') == 1:
            if not self.valid_files(request.form):
                score += waf.config.getint('scorer', 'upload_filetype')

        threshold = waf.config.getint('enforcer', 'request_threshold')

        if score > threshold:
            print bcolors.FAIL + "[THREAT] URL '%s' scored as malicious (%d/%d)." % (path, score, threshold) + bcolors.ENDC
            if waf.config.get('enforcer', 'action') == 'drop':
                return False

    	return True
 
    def analyzeResponse(self, response):

        command = self.client_request.command
        path = self.client_request.path

        # Check if page can be acessed within given method
        waf.cursor.execute("SELECT method FROM urls WHERE path = ? AND method = ? AND type = 'resp' GROUP BY METHOD", (path, command) );
        methods = waf.cursor.fetchone()

        if methods is None:
            print bcolors.WARNING + "[ANOMALY] URL/method ('%s','%s') not in database." % (command, path) + bcolors.ENDC
            if waf.unknown_urls_action == ACTION_PASS:
                return True
            else:
                self.response_buffer = None
                return False

        
        averages = self.fetch_averages(path, 'resp')

        score = 0

        # Header QTY
        avgs = averages[0:3]
        ret = True
        header_qty = len(response.headers)
        tolerance = waf.config.get('tolerance', 'response_header_qty')
        if waf.config.get('analyzer', 'response_header_qty') == 'avg':
            ret = in_average(avgs[2], header_qty, tolerance)
        else:
            ret = in_range(avgs[0], avgs[1], header_qty, tolerance)
        if not ret:
            print bcolors.WARNING + "[ANOMALY] URL '%s' has an unexpected response header quantity (%d)." % (path, header_qty) + bcolors.ENDC
            score += waf.config.getint('scorer', 'response_header_qty')

        # Header SIZE
        avgs = averages[3:6]
        ret = True
        header_size = len(str(response.headers))
        tolerance = waf.config.get('tolerance', 'response_header_size')
        if waf.config.get('analyzer', 'response_header_size') == 'avg':
            ret = in_average(avgs[2], header_size, tolerance)
        else:
            ret = in_range(avgs[0], avgs[1], header_size, tolerance)
        if not ret:
            print bcolors.WARNING + "[ANOMALY] URL '%s' has an unexpected response header size (%d)." % (path, header_size) + bcolors.ENDC
            score += waf.config.getint('scorer', 'response_header_size')

        # Content SIZE
        avgs = averages[6:9]
        ret = True
        content_size = (len(self.response_buffer)-header_size)
        tolerance = waf.config.get('tolerance', 'response_content_size')
        if waf.config.get('analyzer', 'response_content_size') == 'avg':
            ret = in_average(avgs[2], content_size, tolerance)
        else:
            ret = in_range(avgs[0], avgs[1], content_size, tolerance)
        if not ret:
            print bcolors.WARNING + "[ANOMALY] URL '%s' has an unexpected response content size (%d)." % (path, content_size) + bcolors.ENDC
            score += waf.config.getint('scorer', 'response_content_size')

        # Cookies
        if waf.config.getint('analyzer', 'response_cookies') == 1 and 'set-cookie' in response.headers:
            if not self.valid_cookies(response.headers['set-cookie'], 'resp'):
                score += waf.config.getint('scorer', 'response_cookies')

        # Header sanity
        if waf.config.getint('analyzer', 'response_headers') == 1:
            if not self.valid_headers(response.headers.keys(), 'resp'):
                score += waf.config.getint('scorer', 'response_headers')

        threshold = waf.config.getint('enforcer', 'response_threshold')

        if score > threshold:
            print bcolors.FAIL + "[THREAT] URL '%s' scored as malicious (%d/%d)." % (path, score, threshold) + bcolors.ENDC
            if waf.config.get('enforcer', 'action') == 'drop':
                return False

        return True


    # Server => Proxy
    def dataReceived(self, data):

        if waf.mode == MODE_BYPASS:
            self.factory.server.write(data)
            return False

        if self.response_buffer is None:
            self.response_buffer = data
        else:
            self.response_buffer += data

        # All chunks received
        if self.chunked and data.endswith(CHUNK_END):
            self.chunked = False
        elif self.chunked:
            return True

        response = HTTPResponse(self.response_buffer)

        if not hasattr(response, 'headers'):
            print bcolors.FAIL + '[ANOMALY] Malformed response.' + bcolors.ENDC
            self.factory.server.drop_connection()
            self.response_buffer = None
            return False

        # Chunked starts
        if response.chunked is not None and len(self.response_buffer) == len(data):
            self.chunked = True
            return True

        if waf.mode == MODE_OPERATIONAL:
            if not self.analyzeResponse(response):
                self.factory.server.drop_connection()
                self.response_buffer = None
                return False

        header_qty = len(response.headers)
        header_size = len(str(response.headers))
        content_size = (len(self.response_buffer)-header_size)
        print bcolors.OKGREEN + "[RESPONSE] %s %s (HEADERS: %d, HEADERSIZE: %s, CONTENTSIZE %s)" % (self.client_request.command, self.client_request.path, header_qty, header_size, content_size) + bcolors.ENDC

        if waf.mode == MODE_TRAINING:
            self.learnResponse(response)
    
        self.factory.server.write(self.response_buffer)
        self.response_buffer = None

    def learnResponse(self, response):

        header_qty = len(response.headers)
        header_size = len(str(response.headers))
        content_size = (len(self.response_buffer)-header_size)
        waf.cursor.execute('INSERT INTO urls VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (self.client_request.path, self.client_request.command, header_qty, header_size, content_size, None, None, 'resp'))
	
        # Check for cookies
        cookies = []
        if 'set-cookie' in response.headers:
            ck = Cookie.SimpleCookie()
            ck.load(response.headers['set-cookie'])
            for cookie in ck.keys():
                cookie_name = cookie.strip().lower()
                cookies.append((self.client_request.path, self.client_request.command, cookie_name, 'resp'))

        headers = []	
        for header in response.headers:
            header_name = header.strip().lower()
            headers.append((self.client_request.path, self.client_request.command, header_name, 'resp'))
	
        waf.cursor.executemany('INSERT OR IGNORE INTO cookies VALUES (?, ?, ?, ?)', cookies)
        waf.cursor.executemany('INSERT OR IGNORE INTO headers VALUES (?, ?, ?, ?)', headers)

        waf.conn.commit()

    def learnRequest(self, data):

        request = self.client_request

        header_qty = len(request.headers)
        header_size = len(str(request.headers))
        content_size = (len(data)-header_size)

        waf.cursor.execute('INSERT INTO urls VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (request.path, request.command, header_qty, header_size, content_size, None, None, 'req'))

        headers = []	
        cookies = []
        postdata = []
        mimes = []

        if 'Cookie' in self.client_request.headers:
            ck = Cookie.SimpleCookie()
            ck.load(self.client_request.headers['Cookie'])
            for cookie in ck.keys():
                cookie_name = cookie.strip().lower()
                cookies.append((self.client_request.path, self.client_request.command, cookie_name, 'req'))

        for header in self.client_request.headers:
            header_name = header.strip().lower()
            headers.append((self.client_request.path, self.client_request.command, header_name, 'req'))
	
        if request.command == "POST":
            for field in request.form.keys():
                if request.form[field].filename:
                    file_data = request.form[field].file.read()
                    mime = waf.magic.buffer(file_data)
                    mimes.append((self.client_request.path, mime))
                field_name = field.strip().lower()
                postdata.append((self.client_request.path, field_name))

        waf.cursor.executemany('INSERT OR IGNORE INTO cookies VALUES (?, ?, ?, ?)', cookies)
        waf.cursor.executemany('INSERT OR IGNORE INTO headers VALUES (?, ?, ?, ?)', headers)
        waf.cursor.executemany('INSERT OR IGNORE INTO postdata VALUES (?, ?)', postdata)
        waf.cursor.executemany('INSERT OR IGNORE INTO uploads VALUES (?, ?)', set(mimes))

        waf.conn.commit()
 
    # Proxy => Server
    def write(self, data):

        if data:

            if waf.mode == MODE_BYPASS:
                self.transport.write(data)
                return True

            if self.request_buffer is None:
                self.request_buffer = data
            else:
                self.request_buffer += data

            request = HTTPRequest(self.request_buffer)

            if not hasattr(request, 'headers') or not hasattr(request, 'path') or not hasattr(request, 'command'):
                print bcolors.FAIL + '[ANOMALY] Malformed request.' + bcolors.ENDC
                self.factory.server.drop_connection()
                self.request_buffer = None
                return False

            self.client_request = request

            header_qty = len(request.headers)
            header_size = len(str(request.headers))
            content_size = (len(self.request_buffer)-header_size)

            if 'Content-Length' in request.headers:
                total_size = int(request.headers['Content-Length'])
                if content_size < total_size:
                    return True

            if waf.mode == MODE_OPERATIONAL:
                if not self.analyzeRequest():
                    self.factory.server.drop_connection()
                    self.request_buffer = None
                    return False
    
            print bcolors.OKBLUE + "[REQUEST] %s %s (HEADERS: %d, HEADERSIZE: %s, CONTENTSIZE %s)" % (request.command, request.path, header_qty, header_size, content_size) + bcolors.ENDC

            if waf.mode == MODE_TRAINING:
                self.learnRequest(self.request_buffer)

            self.transport.write(self.request_buffer)
            self.request_buffer = None
            return True

class WAF(object):

    conn = None
    config = None
    mode = None
    magic = None

    unknown_ulrs_action = ACTION_DROP

    listen_port = 0
    server_addr = None
    server_port = 0

    def __init__(self):
        self.config = ConfigParser.RawConfigParser()
        self.init_config()
        self.init_logging()
        self.init_magic()
        self.init_db()

    def print_banner(self):

        print textwrap.dedent("""\

             88          88    ad88               88 88                     
             88          ""   d8"                 "" ""                ,d     
             88               88                                       88     
             88,dPPYba,  88 MM88MMM 8b,dPPYba,  ,adPPYba,  ,adPPYba, MM88MMM  
             88P\'    "8a 88   88    88P\'   "Y8 a8"     "8a I8[    ""   88     
             88       d8 88   88    88         8b       d8  `"Y8ba,    88     
             88b,   ,a8" 88   88    88         "8a,   ,a8" aa    ]8I   88,    
             8Y"Ybbd8"\'  88   88    88          `"YbbdP"\'  `"YbbdP"\'   "Y888  
        
             Intelligent Web Application Firewall
             by: Jan Seidl <jseidl@wroot.org>

             """)

    def start(self):
        self.print_banner()
        self.init_reactor()

    def init_db(self):
        self.conn = sqlite3.connect(DATABASE_FILE)
        self.cursor = self.conn.cursor()

    def init_magic(self):
        self.magic = magic.open(magic.MAGIC_MIME)
        self.magic.load()

    def init_config(self):
        try:
            self.config.read(CONFIG_FILE)

            # Mode
            _mode = self.config.get('general', 'mode')
            if _mode == 'training':
                self.mode = MODE_TRAINING
            elif _mode == 'operational':
                self.mode = MODE_OPERATIONAL
            else:
                self.mode = MODE_BYPASS

            # Unknown URLs
            if self.config.get('general', 'unknown_urls') == 'drop':
                self.unknown_urls_action = ACTION_DROP
            else:
                self.unknown_urls_action = ACTION_PASS

        except Exception, e:
            sys.stderr.write("No config file present %s" % str(e))
            sys.exit(1)

    def init_reactor(self):
        factory = protocol.ServerFactory()
        factory.protocol = ServerProtocol

        self.listen_port = self.config.getint('general', 'listen_port')
        self.server_addr = self.config.get('general', 'backend_ip')
        self.server_port = self.config.getint('general', 'backend_port')

        reactor.listenTCP(self.listen_port, factory)
        print bcolors.HEADER + "BWAF listening at port %d (backend: %s:%d) [%s]" % (self.listen_port, self.server_addr, self.server_port, 'operational' if self.mode == MODE_OPERATIONAL else 'training') + bcolors.ENDC
        reactor.run()

    def init_logging(self):
        log.startLogging(sys.stdout)

    def __del__(self):
        if self.conn is not None:
            self.conn.close()

waf = WAF()

def main():

    waf.start()

def reload_waf(signum, frame):

    print bcolors.WARNING + "Received Signal: %s at frame: %s" % (signum, frame) + bcolors.ENDC
    print bcolors.HEADER + "Reloading WAF configuration." + bcolors.ENDC
    waf.init_config()
 
# SIGHUP Reload Config trap
signal.signal(signal.SIGHUP, reload_waf)

if __name__ == '__main__':
    main()
