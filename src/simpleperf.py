import re
import subprocess
import sys
import argparse
import socket
import os
import threading as th
import ipaddress
import time
import json
import math
import DRTP


# a function to run ifconfig on a node and grab the first ipv4 address we find.
# which makes sense to set as default address when running in server mode.
def get_ip():
    # Run the ifconfig command and capture the output, and decode bytes to string
    ifconf = subprocess.check_output(['ifconfig']).decode()

    # Split the output into lines
    ifconf_lines = ifconf.split('\n')

    # if no valid address is grabbed from ifconfig.
    address = False
    # Find the line that contains the IP address
    for line in ifconf_lines:
        if 'inet ' in line:
            address = line.split()[1]
            break
    # return an arbitrary default value, or the one we grabbed.
    if ipaddress.ip_address(address):
        return address
    else:
        return "10.0.1.2"


# function to validate the ip address given as an argument, validatet with a regex pattern and the ipaddress library.
# if we don't have a valid ip address we terminate the program, and print a fault
def valid_ip(inn):  # ip address must start with 1-3 digits seperated by a dot, repeated three more times.
    # I've decided to use an incomplete regex, "257.0.0.0" for example isn't an ip address but this regex allows them.
    # ipaddress however translates input from the user however eg: ipaddress.ip_address(10) returns 0.0.0.10
    # the task specifies that the ipaddress needs to be in a dotted decimal format, this is now achieved.
    ip_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_regex.match(inn):
        print(f"an ipaddress needs to be in a dotted decimal format!\n {inn}, is not!")
        sys.exit(1)
    try:
        ip = ipaddress.ip_address(inn)
    except ValueError:
        print(f"{inn} is not a valid ip address.")
        sys.exit(1)
        # ipaddress returns an IPv4Address object, we cast it to string our use
    return str(ip)


# check if port is an integer and between 1024 - 65535
def valid_port(inn):
    # if the input isn't an integer, we complain and quit
    try:
        ut = int(inn)
    except TypeError:
        raise argparse.ArgumentTypeError(f"port must be an integer, {inn} isn't")
    # if the input isn't within range, we complain and quit
    if not (1024 <= ut <= 65535):
        raise argparse.ArgumentTypeError(f'port number: ({inn}) must be within range [1024 - 65535]')
    return ut


# attempts to grab a specified file.
def valid_file(name):
    abs = (os.path.dirname(__file__))
    path = abs + f"/../img/{name}"
    if os.path.isfile(path):
        return path
    else:
        print(f"couldn't find requested file, please make sure {name} is present in the img folder")
        sys.exit(1)


# parse arguments the user may input when running the skript, some are required in a sense, others are optional
def get_args():
    # start the argument parser
    parse = argparse.ArgumentParser(prog="FileTransfer",
        description="transfer a chosen file between two hosts, uses UDP and "
                    "a custom protocol DRTP for reliable transfer.",
        epilog='simpleperf --help')

    # optional arguments, with long and short name, default values when needed, info for the help page
    parse.add_argument('-s', '--server', action='store_true', help='enables server mode')
    parse.add_argument('-c', '--client', action='store_true', help='enables client mode')
    parse.add_argument('-p', '--port', type=valid_port, default=8088, help="which port to bind/open")
    parse.add_argument('-b', '--bind', type=valid_ip, default=get_ip(),  # attempts to grab ip from ifconfig
                       help="ipv4 adress to bind server to, default binds to local address")
    parse.add_argument('-t', '--test', choices=['norm', 'loss', 'skipack', 'neteem', 'skipseq'], default="norm",
                       help="run tests on a server, loss drops some packets, skipack skips acking some packets,"
                            "neteem implements tc-netem")

    # client arguments ignored if running a server
    parse.add_argument('-I', '--serverip', type=valid_ip, default="10.0.1.2",  # default value is set to node h3
                       help="ipv4 address to connect with, default connects with node h1")
    parse.add_argument('-f', '--file', type=valid_file, default="kameleon.jpg",
                       help="specify a file in the img folder to transfer, defaults to supplied kameleon.jpg")
    parse.add_argument('-r', '--reli', choices=['sw', 'sr', 'gbn'], default="sw",
                       help='choose which method used for reliable transfer, '
                            'sw is stop wait, gbn is go back n, sr is selective repeat.')

    # parse the arguments
    return parse.parse_args()


args = get_args()

# an instance of simpleperf may only be server or client, this functions as an xor operator
if not (args.server ^ args.client):
    raise AttributeError("you must run either in server or client mode")


def client():
    if args.reli == "gbn":
        method = DRTP.GoBackN(args.bind, args.serverip, args.port)
    elif args.reli == 'sr':
        method = DRTP.SelectiveRepeat(args.bind, args.serverip, args.port)
    else:
        method = DRTP.StopWait(args.bind, args.serverip, args.port)


    # create connection type based upon the arguments.
    # open a socket using ipv4 address(AF_INET), and a UDP connection (SOCK_DGRAM)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as cli_sock:

        method.set_con(cli_sock)
        with open(args.file, 'rb') as fil:
            chunk = fil.read(1460)
            while chunk:
                method.send(chunk)
                chunk = fil.read(1460)


def server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as serv_sock:
        serv_sock.bind((args.bind, args.port))
        print(f"server at {args.bind}:{args.port} is ready to receive")
        while True:
            # recieve first syn from client
            try:
                data, addr = serv_sock.recvfrom(500)
            except KeyboardInterrupt:
                print("Keyboard interrupt recieved, exiting server")
                sys.exit(1)

            header = data[:12]
            body = data[12:]
            print(len(header))
            en_client = json.loads(body.decode())

            # creates a "creates" a clone of the client attempting to connect.
            if en_client['typ'] == 'GoBackN':
                remote_client = DRTP.GoBackN(args.bind, en_client['laddr'], args.port)
            elif en_client['typ'] == 'StopWait':
                remote_client = DRTP.StopWait(args.bind, en_client['laddr'], args.port)
            elif en_client['typ'] == 'SelectiveRepeat':
                remote_client = DRTP.SelectiveRepeat(args.bind, en_client['laddr'], args.port)
            else:
                print("client information insuficient, exiting")
                sys.exit()

            # hands the socket over,
            remote_client.set_con(serv_sock)
            # responds to the client, and let them know we are ready to recieve
            remote_client.answer_hello(header)

            chunks = []

            """while remote_client.fin == 0:
                chunks.append(remote_client.recv(1500))"""


if args.server:
    server()
else:
    client()
