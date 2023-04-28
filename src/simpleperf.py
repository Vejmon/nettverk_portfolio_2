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

def valid_rtt(inn):
    # if the input isn't a float, we complain and quit
    try:
        ut = float(inn)
    except TypeError:
        raise argparse.ArgumentTypeError(f"RTT must be a float, {inn} isn't")
    # if the input isn't within range, we complain and quit
    if not (1 <= ut):
        raise argparse.ArgumentTypeError(f'RTT: ({inn}) must be a positive float')
    return ut

# check if the argument deciding window size is valid.
def valid_window(inn):
    # if the input isn't an integer, we complain and quit
    try:
        ut = int(inn)
    except TypeError:
        raise argparse.ArgumentTypeError(f"window must be an integer, {inn} isn't")
    # if the input isn't within range, we complain and quit
    if not (1 <= ut ):
        raise argparse.ArgumentTypeError(f'window number: ({inn}) must be a positive integer')
    return ut

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
    abs = os.path.dirname(__file__)
    path = abs + f"/../img/{name}"
    if os.path.isfile(path):
        return path
    else:
        print(f"couldn't find requested file, please make sure {name} is present in the img folder")
        sys.exit(1)

# modifisert denne noe:
# https://stackoverflow.com/questions/13852700/create-file-but-if-name-exists-add-number
def get_save_file(path):
    file = path.split('/')[-1]
    filename, extension = os.path.splitext(file)

    counter = 1
    while os.path.exists(path):
        file = path.split('/')[-1]
        path = path[:-len(file)] + filename + "(" + str(counter) + ")" + extension
        counter += 1
    return path


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
    parse.add_argument('-f', '--file', type=valid_file, default="kameleon.jpg", #alle_dyr.png
                       help="specify a file in the img folder to transfer, defaults to supplied kameleon.jpg")
    parse.add_argument('-r', '--reli', choices=['sw', 'sr', 'gbn'], default="sw",
                       help='choose which method used for reliable transfer, '
                            'sw is stop wait, gbn is go back n, sr is selective repeat.')
    parse.add_argument('-w', '--window', type=valid_window, default=5,
                       help='window size used for reliable transfer, when using "go back n" or "selective repeat"'
                            'window size must be a positive integer')
    parse.add_argument('-R', '--RTT', type=valid_rtt, default=0.05,
                       help='set round-trip-time for the client connection in ms, may be a float.'
                            'RTT must be a positive float.')

    # parse the arguments
    return parse.parse_args()


args = get_args()

# an instance of simpleperf may only be server or client, this functions as an xor operator
if not (args.server ^ args.client):
    raise AttributeError("you must run either in server or client mode")


def client():

    # sets method for reliable transfer.
    if args.reli == "gbn":
        method = DRTP.GoBackN(args.bind, args.serverip, args.port)
    elif args.reli == 'sr':
        method = DRTP.SelectiveRepeat(args.bind, args.serverip, args.port)
    else:
        method = DRTP.StopWait(args.bind, args.serverip, args.port)
    # binds UDP connection to local ipv4 address and port.
    method.bind_con()

    # let server know we are trying to connect,
    # the argument send is the filename we are going to attempt to transmit
    method.send_hello(args.file.split('/')[-1])

    # sender pakker så lenge det fins deler å lese og forige sending gikk bra
    send_succesfull = True
    with open(args.file, 'rb') as fil:
        chunk = fil.read(1460)
        # create first packet so that we don't send an extra empty packet.

        while chunk:
            if send_succesfull:
                send_succesfull = method.send(chunk)
            else:
                print("sending failed! exiting")
                sys.exit(1)
            chunk = fil.read(1460)


def server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as serv_sock:
        serv_sock.bind((args.bind, args.port))
        while True:
            print(f"server at {args.bind}:{args.port} is ready to receive")
            # wait indefinetly for a new connection
            serv_sock.settimeout(None)

            # recieve first syn from client
            try:
                data, addr = serv_sock.recvfrom(500)
            except KeyboardInterrupt:
                print("Keyboard interrupt recieved, exiting server")
                sys.exit(1)

            # grab header and body from the packet.
            header, body = DRTP.split_packet(data)
            # if an old client is still attempting to send packets, there might be some issues
            try:
                en_client = json.loads(body.decode())
            except UnicodeDecodeError:
                serv_sock.close()
                print("wrong packet received, body is not a JSON!, restarting server")
                break


            # create a server version of the client attempting to connect,
            # we grab the -r and -f flag from the client. (reliable method and filename)
            if en_client['typ'] == 'GoBackN':
                remote_client = DRTP.GoBackN(args.bind, en_client['laddr'], args.port)
            elif en_client['typ'] == 'StopWait':
                remote_client = DRTP.StopWait(args.bind, en_client['laddr'], args.port)
            elif en_client['typ'] == 'SelectiveRepeat':
                remote_client = DRTP.SelectiveRepeat(args.bind, en_client['laddr'], args.port)
            else:
                # quit if something unforeseen has happened
                print("client information insuficient, exiting")
                sys.exit()

            # hands over the received header from the connected client
            remote_client.remote_header = header

            # hands the socket over, for future transfers.
            remote_client.set_con(serv_sock)

            print("mottat header")
            print(remote_client.remote_header)

            # start over if the remote client doesn't respond to our answer
            if remote_client.answer_hello():
                # lager en fil fil i ut mappen
                # hvis filen fins, inkrementerer med 1
                filnavn = en_client['fil']
                abs = os.path.dirname(__file__)
                # hopper ut av src mappen
                abs = abs[:-4]
                path = abs + f"/ut/{filnavn}"
                # ser om filen allerede fins, lager nytt navn i det tilfelle
                unik_fil = get_save_file(path)
                # lager en tom fil.
                open(unik_fil, "xb")

                # write to file as long as transmission isn't done and there is something in data.
                while not remote_client.local_header.get_fin() and data:
                    data = remote_client.recv(1500)
                    if data:
                        with open(path, "ab") as skriv:
                            skriv.write(data)

                # we can infer that the transfer failed if we never got a fin flag,
                # in that case we remove the half transfered file.
                if not remote_client.remote_header.get_fin():
                    print("removing failed file")
                    os.remove(path)
                # else:
                # remote_client.answer_fin() fix fix

        # restarts server after an error ocurs
        time.sleep(3)
        server()

if args.server:
    server()
else:
    client()
