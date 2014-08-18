This script check if DANE certificate is the certificate sent by server.
If domain name don't use DANE to validate servers, result will be negative.

DANE is a protocol to validate SSL certificate by a domain name service secured by DNSSEC.
You can have more informations on http://www.bortzmeyer.org/6698.html.

# How to install 

    pip install -r requirements.txt

# How to check example.com

    python check_dane.py -H example.com
    example.com True

If you want to test multiples servers in the same time, you can chain it

	python check_dane.py -H example.com toto.com
    example.com True
    toto.com True

