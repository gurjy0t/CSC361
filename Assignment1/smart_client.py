"""
@Author: Gurjyot Grewal
StudentID: V00820022
Class: CSC361

Basic function: Given URI/URL determine highest HTTP, HTTPS usage and used cookies
Usage information and other details can be found in the README.txt file

References: 
[1] RFC 2616 - Hypertext Transfer Protocol -- HTTP/1.1", Tools.ietf.org, 2018. [Online].
    Available: https://tools.ietf.org/html/rfc2616. [Accessed: 26- Jan- 2018].

[2] List of User Agent Strings :: udger.com", udger.com, 2018. [Online].
    Available: https://udger.com/resources/ua-list. [Accessed: 26- Jan- 2018].

[3] HTTP cookies", Mozilla Developer Network, 2018. [Online].
    Available: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies. [Accessed: 26- Jan- 2018].
"""

import sys
import argparse
import socket
import ssl
from urllib.parse import urlparse

def smart_client(uri):
    """
    This is the function which is called from the main method.
    Redirection handling is done here based on returned values from other functions

    @params: URI
    
    No return value, this function prints
    """
    original_uri = uri
    http = "1.0"
    use_https = check_https(uri)
    redir = True
    count = 0
    u_p = True
    while redir:
        response_status,  \
        response_headers, \
        highest_http,     \
        redirect,         \
        location,         \
        new_https,        \
        use_upgrade = get_highest_http(uri, use_https, u_p)
        redir = redirect
        http = highest_http
        u_p = use_upgrade
        if response_status == "101":
            http = "2.0"
        use_https = new_https

        if redirect:
            count += 1
            uri = location
    nice_cookies = get_cookies(response_headers)

    print('\nTesting Website: ' + original_uri)
    if original_uri != uri:
        print(
            'The input website redirected ' + str(count) +
            ' times and ended at a final location of ' + uri
        )
    print('1. Support of HTTPS: ' + str(use_https))
    print('2. The newest version of HTTP the server supports is : ' + http)
    print('3. =================== Cookies =================== \n')

    if len(nice_cookies) is 0:
        print(
            'This site did not set any cookies on the browser directly.' +
            'Other cookies may be set through on-site events\n'
        )

    else:
        for cookie in nice_cookies:
            if len(cookie) == 3:
                print('Name/Key: ' + cookie[0]  + ', Domain: '+ cookie[2]+'\n')
            else:
                print('Name/Key: ' + cookie[0] + ', Domain: None provided in the response\n')

def get_cookies(headers):
    '''
    This function, given cookies, splits the cookies by their delimiters
    and returns a list of lists representing cookies and their name/value/domain

    params: headers list [], with each element representing a header returned from server
    return: a list of lists representing cookies, each with format [name, value, domain]
    '''

    cookies = []
    nice_cookies = []
    cookie_id = 'Set-Cookie'
    domain_id = 'domain'

    for header in headers:
        if 'Set-Cookie' in header:
            cookies.append(header)

    for cookie in cookies:
        n_c = []
        components = cookie.split(';')  #[3]
        for component in components:
            if cookie_id in component:
                c_k = component.split(' ')

                split_index = [
                    index for index, character in enumerate(c_k[1]) if character == '='
                ][-1]  #Find rightmost equal sign for cookies with multiple ='s
                name = c_k[1][:split_index]
                n_c.append(name)
                n_c.append(component.split(' ')[1].split('=')[1])
            if domain_id in component:
                n_c.append(component.split('=')[1])
        nice_cookies.append(n_c)
    return nice_cookies

def connect_to(uri, https=True, h_2=False):
    '''
    Connects to specified uri if domainname resolves to IP.

    @params: required = uri, optional = https and h2
    @return: (socket, error) tuple. Error is a boolean
    '''
    h_p = get_host(uri)
    i_p = check_host_name(h_p[0])
    port = 443 if https else 80
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if https:
        ctx = ssl.create_default_context()
        alpn_protocols = ['h2', 'http/1.1', 'http/1.0'] if h_2 else ['http/1.1', 'http/1.0']
        ctx.set_alpn_protocols(alpn_protocols)
        ssl_sock = ctx.wrap_socket(sock, server_hostname=uri)
        sock = ssl_sock
    try:
        sock.settimeout(4)
        sock.connect((i_p, port))
        sock.settimeout(None)
    except socket.error:
        return sock, True
    except socket.timeout:
        return sock, True
    except ssl.CertificateError:
        return sock, True
    return sock, False

def send_and_recieve(sock, request):
    '''
    Function to send request, receive data and close connection

    @params: socket and request (in bytes)
    @return: Response headers as a list, each representing one header
    '''
    sock.sendall(request)
    response = receive_data(sock).decode().split('\r\n')    #[1]
    sock.close()
    return response

def check_https(uri):
    '''
    This method ensure that the uri accepts connections on port 443 and does not redirect to http

    @params: uri
    @return: Boolean
    '''
    h11_request = b"HEAD / HTTP/1.1\r\nHost: "+ uri.encode()+ b"\r\n\r\n"   #[1]
    o_k = '200'
    ssl_sock, error = connect_to(uri, True)
    if error:
        return False
    received = send_and_recieve(ssl_sock, h11_request)
    status_line = received[0]

    #200 if https support.
    #302 to http if no support (and not cert error or connection reject)
    #or 302 to .ca/.co.uk/.in based on locale but https support.
    if o_k not in status_line:
        for header in received:
            if 'Location' in header:
                if 'https' in header:
                    return True
                return False
        return False
    return True

def get_host(uri):
    '''
    This method does some url parsing for the different cases.

    @params: uri
    @return: (netloc, path) tuple
    '''
    o = urlparse(uri)
    netloc = o.netloc
    path = o.path
    scheme = o.scheme
    r_v = netloc, '/'

    if netloc == '':
        slash_locations = [index for index, character in enumerate(path) if character == '/']
        num_slashes = len(slash_locations)
        if num_slashes > 2 and scheme != '':
            netloc = path[len(scheme)+2:slash_locations[2]]
            path = path[slash_locations[2]:]
            r_v = netloc, path
        elif num_slashes > 2 and scheme == '':
            netloc = path[:slash_locations[0]]
            path = path[slash_locations[0]:]
            r_v = netloc, path
        elif num_slashes < 2 and num_slashes != 0:
            netloc = path[:slash_locations[0]]
            path = path[slash_locations[0]:]
            r_v = netloc, path
        elif num_slashes == 0:
            r_v = path, '/'
        return r_v
    return (netloc, path) if path != '' else (netloc, '/')

def receive_data(sock):
    '''
    This method recieves header data from the socket provided.

    @params: A socket object waiting to recieve an HTTP(1/1.1) response
    @return: raw headers as bytes

    '''
    received = b""
    while True:
        msg = sock.recv(1024)
        received = received + msg
        time_to_close = check_for_eom(msg)

        if '\r\n\r\n' in received.decode():
            received = (received.decode().split('\r\n\r\n')[0]).encode()
        if not msg or time_to_close:
            sock.close()
            break
    return received

def get_highest_http(uri, https, upgrade=True):
    """
    This method determines the highest http a server can support.
    This is done over http or https, depending on the parameter.
    HTTP2 is checked but never used to exchange messages.

    @params: uri, https, upgrade (used during h2 check over http)
    @return: (response_status, response_headers, highest_http, redirect, location, use_https, upgrade)
             response_status, response_headers & highest_http represent data extracted from header.
             redirect and location, are used for redirection control in case of 302/301's
             use_https is a boolean in case the redirection takes the program to an http site
             upgrade is also a booean, only used on the subsequent request to a server which
             accepts h2 but not https. 
    """
    highest_http = '1.0'
    response_status = ""
    redirect = False
    location = ""
    port = 443 if https else 80
    use_https = https
    use_upgrade = upgrade
    host, path = get_host(uri)
    i_p = check_host_name(host)
    request_line = "GET "+ path +" HTTP/1.1\r\n"
    headers_line = "Host: "+ host+ "\r\n"

    upgrade_line = "Connection: close\r\nUpgrade: h2c\r\n\r\n" if not https \
    else "Connection: Close\r\nuser-agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US)"+ \
         "AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.375.86 Safari/533.4\r\n\r\n" #[3]

    h11_request = (request_line+headers_line+upgrade_line).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2', 'http/1.1', 'http/1.0'])
        ssl_sock = ctx.wrap_socket(sock, server_hostname=host)
        sock = ssl_sock
    try:
        sock.settimeout(5)
        sock.connect((i_p, port))
        sock.settimeout(None)
    except socket.error:
        print("The socket can't seem to connect,"+
              "even though host name was resolved for the provided URI")
        sys.exit()
    except socket.timeout:
        print("A timeout occured because the host failed to connect for 5 seconds")
    if https:
        proto = sock.selected_alpn_protocol()
        if proto == 'h2':
            highest_http = '2.0'
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(['http/1.1', 'http/1.0'])
            ssl_sock = ctx.wrap_socket(sock, server_hostname=host)
            sock = ssl_sock
            sock.connect((i_p, port))

    rec = send_and_recieve(sock, h11_request)
    sock.close()
    status_line = rec[0]
    response_headers = rec[1:]

    if highest_http != '2.0':
        highest_http = "1.0" if 'HTTP/1.0' in status_line else "1.1"
        if not https and '101' in status_line:
            highest_http = "2.0"


    if  '200' not in status_line and '204' not in status_line and  '205' not in status_line:
        if '302' in status_line or '301' in status_line:

            redirect = True

            for header in response_headers:
                if 'Location' in header:
                    if 'https' in header:
                        use_https = True
                    redirect = True
                    location = (header.split(" ")[1])
                    if location == uri:
                        print("This site keeps redirecting to itself and returning 302's Something is wrong")
                        redirect = False
                    break
        elif '101' in status_line:
            use_upgrade = False
            location = uri
            redirect = True
        elif '500' in status_line or '505' in status_line:
            print("Recieved a 5xx response from the server at location: " + uri  +" exiting now...")
            sys.exit()
        elif '404' in status_line:
            print("The specified host exists but the path " + path + " was not found")
            sys.exit()
        else:
            print('An unexpected response status of ' +status_line.split(" ")[1] +' was received from site "' + uri +'"')
            sys.exit()

    response_status = status_line.split(" ")[1]
    tup = (
        response_status,
        response_headers,
        highest_http,
        redirect,
        location, use_https,
        use_upgrade
        )
    return tup

def check_for_eom(msg):
    '''
    Checks for a delimiter in the message, representing end of message (header).

    @params: msg (in bytes)
    @return: Boolean
    '''
    # From RFC2616 the response header (in case of HEAD there is no body) will end with 2 CLRF's [2]
    two_clrf = b'\r\n\r\n'
    if two_clrf in msg:
        return True
    return False

def check_host_name(uri):
    '''
    Checks whether the domain name resolves to a valid IP addr

    @params: uri
    @return: ip or exit the system if given host name cannot be resolved
    '''
    try:
        i_p = socket.gethostbyname(uri)
        return i_p
    except socket.gaierror:
        # this means could not resolve the host
        print("There was an error resolving the host, please check the URI and try again."
              "The uri was: "+ uri)
        sys.exit()

def main():
    """
    Passes CL args to smart_client()
     """
    parser = argparse.ArgumentParser()
    parser.add_argument("URI")
    args = parser.parse_args()
    smart_client(args.URI)

if __name__ == '__main__':
    main()
