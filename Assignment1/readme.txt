README:

This is the readme for smart_client.py, an application built for CSC361 Assignment 1. The purpose of this application
is to, given a URI, determine; if the server accepts HTTPS, the highest accepted HTTP version and the names/domains
for all cookies set by the server. 

This application requires Python3 version 3.6 in order to function properly.

USAGE:
 	python3 smart_client.py <URI>
	
	To use the smart_client app, run the above where uri is a netlocation without the scheme: www.<domainname>.<TLD>

	NOTE: If you have multiple python versions installed, please ensure you are using the correct one
	by typing 'python --version' or 'python3 --version' or 'python3.6 --version.' Every case differs.

Example:	
	python3 smart_client.py www.google.com



MORE:

This readme will also justify some of the decisions made and reasons for some duplicity in the code, which may 
go against best practices. First, the basic idea behind the app will be discussed.


Basic Idea:

1. First check https (just in case some sites accept https but redirect to http ex:bbc.com)
2. Check highest http (either over http or https, depending on 1)

IF checking highest http over https THEN check for h2 using alpn ELSE add Upgrade header and expect 101 
IF highest http in 2 is HTTP/2 THEN re-connect using http/1.1 (This is done to avoid using h2/hpack)


Some decisions and their justifications:

Lines 275-285 in method get_highest_http(), this closing and reopening of a socket is done to switch back from HTTP/2 if selected by the server. 
The reason this was not abstracted away into something like connect_to() is because of issues that were experienced
in recieving data when this was attempted. The decision to duplicate some connection/instantiaion code in these lines 
was made by prioritizing utility over elegance for the sake of this assignment.


Recieving messages by delimiter '\r\n\r\n' instead of timing out or using the basid 'if not msg' syntax. This was done
because I had issues with the code just hanging at the .recv(size) part and blocking when the server is sending less 
than size data. I use the \r\n\r\n to delimit because the standard, RFC 2616[1], states that each header must be 
seperated by a '\r\n' and the headers and body section must be seperated by an additional '\r\n.' Since the information
we care about is just in the headers, this suffices. However, if i wanted to get more cookies, I would need to get the 
body as well, so as to parse the JS and see all cookie-setting events. 
** A HEAD approach was first used, but replaced with GET when www.aircanada.com blocked HEAD requests **

The decision to mimic a google chrome user-agent arose from a sample case of www.yahoo.com. This website did not return
any cookies in the header, unless a user-agent was set, mimicing a web browser. The string for the user-agent was 
obtained from [2]

The decision to turn check_hostname off and cert_req to CERT_NONE was made due to websites like www.uvic.com
which do not possess a valid SSL certificate. In terms of HTTPS, any website which does not have a valid SSL cert
is not considered to accept HTTPS. This is done in this way, because https support of the command line argument is 
tested first. If this site does not support HTTPS, then everything will be done over HTTP. However, there are some cases
where a website, like www.uvic.com, will accept HTTPS, redirect to https://www.uvic.com and then not have a valid cert
but still redirect to https://www.uvic.ca, which has a valid cert. This, intermediate address, and a very very edgecase
is the reason the options were turned off for the method get_highest_http() but not for check_https()

References:

[1] RFC 2616 - Hypertext Transfer Protocol -- HTTP/1.1", Tools.ietf.org, 2018. [Online]. 
    Available: https://tools.ietf.org/html/rfc2616. [Accessed: 26- Jan- 2018].

[2] List of User Agent Strings :: udger.com", udger.com, 2018. [Online].
    Available: https://udger.com/resources/ua-list. [Accessed: 26- Jan- 2018].
