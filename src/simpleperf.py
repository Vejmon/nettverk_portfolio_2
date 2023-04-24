import re
import subprocess
import sys
import argparse
import socket
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


# if the client doesn't specify a file, we use the default file.
def default_file():
    try:
        fil = open('../img/kameleon.jpg', 'r')
    except FileNotFoundError:
        print('Fatal error, could not find default file')
        print('please make sure kameleon.jpg is present in the img folder')
        sys.exit(1)
    return fil

# attempts to grab a specified file.
def valid_file(name):
    try:
        fil = open(f"../img/{name}", 'r')
    except FileNotFoundError:
        print('Fatal error, could not find requested file')
        print(f"please make sure {name} is present in the img folder")
        sys.exit(1)
    return fil


# checks input for a valid type of !JOBBHER!
def valid_method(inn):
    if inn == 'gbn':
        return DRTP.GoBackN
    if inn == 'sr':
        return DRTP.SelectiveRepeat
    else:
        print(f"-r, --reli flag used incorectly, {inn} is not a method for reliable transfer")
        print("method defaults to StopGo")
        return DRTP.StopGo


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

    # server arguments ignored if running a server
    parse.add_argument('-b', '--bind', type=valid_ip, default=get_ip(),  # attempts to grab ip from ifconfig
                       help="ipv4 adress to bind server to, default binds to local address")
    parse.add_argument('-t', '--test', choices=['norm', 'loss', 'skipack', 'neteem'], default="norm",
                       help="run tests on a server, loss drops some packets, skipack skips acking some packets,"
                            "neteem implements tc-netem")

    # client arguments ignored if running a client
    parse.add_argument('-I', '--serverip', type=valid_ip, default="10.0.1.2",  # default value is set to node h3
                       help="ipv4 address to connect with, default connects with node h1")
    parse.add_argument('-f', '--file', type=valid_file, default=default_file,
                       help="specify a file in the img folder to transfer defaults to supplied kameleon.jpg")
    parse.add_argument('-r', '--reli', type=valid_method, default=DRTP.StartStop,
                       help='choose which method used for reliable transfer, sg is stop_go, gbn is go back n,'
                            'sr is selective repeat.')



    # parse the arguments
    return parse.parse_args()


args = get_args()

# an instance of simpleperf may only be server or client, this functions as an xor operator
if not (args.server ^ args.client):
    raise AttributeError("you must run either in server or client mode")

def client():

    # create connection type based upon the arguments.
    # open a socket using ipv4 address(AF_INET), and a UDP connection (SOCK_DGRAM)
    DRTP.A_Con
    while not connected_list.all_connected():
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            client_sock.connect((args.serverip, args.port))
        except ConnectionError:
            print(f"Connection to {args.serverip}:{args.port} has failed, quitting!")
            sys.exit(1)

        # create a client, and send it to the server.
        laddr, lport = client_sock.getsockname()

        # if num flag is set we create a NumClient, otherwise we make a TimeClient.
        # since the timeflag is set by default. we then add the client to our list of clients.
        if args.num:
            en_client = NumClient(laddr, lport, args.interval,
                                  args.num, args.format, args.parallel, client_sock)
            connected_list.connections.append(en_client)
        else:
            en_client = TimeClient(laddr, lport, args.interval,
                                   args.time, args.format, args.parallel, client_sock)
            connected_list.connections.append(en_client)

        # to catch if all connection are from the same client I've added this id variable,
        # read more below in server_handle_clients
        en_client.set_id(id(connected_list))

        # let server know som info about our client
        client_sock.send(en_client.__str__().encode())

    #let server create clients and catch up
    time.sleep(0.3)


    # start a transmission with either time constraint or bytes.
    if args.num:
        num_client(connected_list)
    else:
        time_client(connected_list)


# clients is a ConnectedClients class.
# this function is used to start threads which shall receive bytes until a "BYE" is received.
# we also wanẗ to do some generall checkups of how the transmission is going and if all connections fail,
# we print what we got and exit.
def server_handle_clients(clients):
    # we first check that all the connections we got are from the same client,
    # I believe I have a bug here, that if two clients open a connection at the exact same time.
    # the list of clients may be a mixed list. I haven't been able to recreate this bug, but I believe it's there.
    if clients.mixed_clients():
        print("fatal error, mixed set of connected clients, server shutting down!")
        for c in clients:
            c.con.close()
        sys.exit()

    # print a statement about each connection
    for c in clients.connections:
        c.print_connection_statement()

    # print a header for the recieving of bytes
    print(f"{dashes}\n{server_header}\n")

    # check the time and store it in a variable
    start = time.time()
    # start individual threads that recieve bytes from their connection, until they are signaled done, or fail
    for c in clients.connections:
        th.Thread(target=c.recieve_bytes, daemon=True).start()

    # periodically check if we are done recieving bytes.
    while not clients.all_done():
        time.sleep(0.1)

    # print the total calculation from the different connections
    for c in clients.connections:
        c.server_print(c.time_done, start)


# sets up basic functionality of a server using socket, starts recieving and putting client connections into groups.
# then starts a thread to handle a group of connected clients.
def server():
    # open a socket using ipv4 address(AF_INET), and a TCP connection (SOCK_STREAM)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as servsock:
        # attempt to bind to port, quit if failed.
        try:
            servsock.bind((args.bind, args.port))
        except ConnectionError:
            print(f'bind failed to port: {args.port},  quitting')
            sys.exit(1)

        # makes servsock a listening connection, ready to accept incoming client connections.
        servsock.listen()
        print(f"{dashes}\n   a simpleperf server is listening on <{args.bind}:{args.port}>\n{dashes}")

        # server = conn(args.bind, args.port)
        # accepts a connection and a ConnectedClients class to handle connected clients.
        connected_clients = ConnectedClients()
        # perpetually recieve a connection, and a client, creates a group of connections and then handles them
        while True:
            # accepts an incoming client and receive info about the connection.
            try:
                con, addr_info = servsock.accept()
            # quit if the user terminates the program
            except KeyboardInterrupt:
                print("keyboard interrupt recieved, attempting to shut down")
                servsock.close()
                sys.exit(1)
            # quit if the connection fails for some reason
            except ConnectionError:
                print("Connection failed, attempting to shut down")
                servsock.close()
                sys.exit(1)

            # assign remote address and port
            raddr, rport = con.getpeername()

            # recieve a json object containing information about the clients attempting to connect to our server.
            setup = json.loads(con.recv(1024).decode())
            # grab the parallel variable from the clients.
            connected_clients.set_parallel(setup['parallel'])

            # create an AllClient from the recieved setup info.
            # since we don't care on the server side wether the constraint is number of bytes, or time.
            try:
                remote_client = AllClient(raddr, rport, setup['interval'],
                                          setup['form'], setup['parallel'], con)
            except ValueError:
                print(f"fatal error, couldn't create client from {raddr}:{rport}")
                sys.exit(1)

            # add the connection to the list of connections.
            connected_clients.connections.append(remote_client)
            # if the list is full, we start a new one, ready to recieve a new batch of connections.
            # we also start a thread to handle the connections we just recieved.
            if connected_clients.all_connected():
                # start a thread which is deamon, so it quits when main thread quits.
                th.Thread(target=server_handle_clients, args=(connected_clients,), daemon=True).start()
                # create a new group
                connected_clients = ConnectedClients()


# if in server mode run server, otherwise run client mode
if args.server:
    server()
else:
    client()
