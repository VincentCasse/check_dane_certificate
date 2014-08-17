import socket
from OpenSSL import SSL
import argparse
import sys
import dns.resolver

"""
Check if ssl certificate provide by a server
is the same sent by dns (DANE protocol)
"""


def get_remote_certificate(host, port):
    """
    Return certificate of remote server

    Arguments:
    - host: server host of server who propose tlsa
    - port: server port of server who propose tlsa
    """
    addr = socket.getaddrinfo(host, port)[0]

    context = SSL.Context(SSL.SSLv23_METHOD)

    if addr[0] == socket.AF_INET6:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
        sock = SSL.Connection(context, sock)
        sock.connect((addr[4][0], port, 0, 0))
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock = SSL.Connection(context, sock)
        sock.connect((addr[4][0], port))

    sock.do_handshake()
    return sock.get_peer_certificate().digest('sha256').upper()


def get_tlsa(host, port):
    """
    Return TLSA dns field. If is not exist

    Arguments:
    - host: server host of server who propose tlsa
    - port: server port of server who propose tlsa
    """
    try:
        tlsa_name_field = '_' + str(port) + '._tcp.' + host
        tlsa_field = dns.resolver.query(tlsa_name_field, 'TLSA')[0].to_text()
    except (dns.resolver.NXDOMAIN):
        return None
    return tlsa_field.split(' ')[3].upper()


def main(argv):
    parser = argparse.ArgumentParser(
        prog='check_dane_validity',
        description='Check if DANE field equals to server certificate')
    parser.add_argument(
        '-s', '--host',
        nargs='+',
        help='host to check')
    parser.add_argument(
        '-p', '--port',
        nargs='?',
        type=int,
        default=443,
        help='port with ssl certificate')
    args = parser.parse_args()

    for host in args.host:
        remote_certificate = get_remote_certificate(host, args.port)
        remote_certificate = remote_certificate.replace(':', '')
        tlsa_field = get_tlsa(host, args.port)
        print host + ' ' + str(tlsa_field == remote_certificate)

if __name__ == "__main__":
    main(sys.argv[1:])
