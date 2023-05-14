import re
import subprocess
import sys
import argparse
import socket
import os
import ipaddress
import time
import json
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


# function to validate the ip address given as an argument, validated with a regex pattern and the ipaddress library.
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


# check if the argument deciding window size is valid.
def valid_window(inn):
    # if the input isn't an integer, we complain and quit
    try:
        ut = int(inn)
    except TypeError:
        raise argparse.ArgumentTypeError(f"window must be an integer, {inn} isn't")
    # if the input isn't within range, we complain and quit
    if not (1 <= ut):
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


# checks if the specified file is in the filesystem.
def valid_file(name):
    absolute = os.path.abspath(os.path.dirname(__file__))
    path = absolute + f"/../img/{name}"
    if os.path.isfile(path):
        return path
    else:
        print(f"couldn't find requested file, please make sure {name} is present in the img folder")
        sys.exit(1)


# used to get a new name to save incoming file to in the ut folder,
# example kameleon.jpg already exists, we increment to kameleon_1.jpg
# looked at how to perform this task on this site:
# https://stackoverflow.com/questions/13852700/create-file-but-if-name-exists-add-number
def get_save_file(path):
    # get full filename
    file = path.split('/')[-1]
    # seperate filename and extension
    filename, extension = os.path.splitext(file)

    counter = 1
    # loop while a file exists
    while os.path.exists(path):
        # filename size increases when numbers are added
        file = path.split('/')[-1]

        # create a new name
        path = path[:-len(file)] + filename + "_" + str(counter) + extension
        counter += 1
    return path


# parse arguments the user may input when running the skript, some are required in a sense, others are optional
# the "help" message may be accessed by invoking the program with the -h flag
def get_args():
    # start the argument parser
    parse = argparse.ArgumentParser(prog="FileTransfer application, made using python 3.10, "
                                         "intended to run on end hosts in a mininet network",
                                    description="transfer a chosen file between two hosts, uses UDP and "
                                                "a custom protocol DRTP for reliable transfer.\n"
                                                "needs a file in the 'img' folder and the 'ut' folder to be present",
                                    epilog='application.py --help')

    # optional arguments, with long and short name, default values when needed, info for the help page
    parse.add_argument('-s', '--server', action='store_true', help='enables server mode')
    parse.add_argument('-c', '--client', action='store_true', help='enables client mode')
    parse.add_argument('-p', '--port', type=valid_port, default=8088, help="which port to bind/open, default is 8088")
    parse.add_argument('-b', '--bind', type=valid_ip, default=get_ip(),  # attempts to grab ip from ifconfig
                       help="ipv4 adress to bind server to, default attempts to bind to local address")
    parse.add_argument('-t', '--test', choices=['skipack', 'skipseq', 'reorder', 'dupack'], default="",
                       help="run tests on a server or client,"
                            " skipack skips acking the second packet, skipseq skips the second sequence nr."
                            " Reorder reorders the packets in the first window only, works with gbn and sr"
                            " dupack duplicates the second ack from server."
                            " NOTE: requires filesize to be greater than 1460 Bytes, "
                            " or a full window when running reorder")

    # client arguments ignored if running a server
    parse.add_argument('-I', '--serverip', type=valid_ip, default="10.0.1.2",  # default value is set to node h3
                       help="ipv4 address to connect with, default connects with node h3 at 10.0.1.2")
    parse.add_argument('-f', '--file', type=valid_file, default="alle_dyr.png",  # kameleon.jpg , sopp.jpg
                       help="specify a file in the img folder to transfer, defaults to supplied alle_dyr.png")
    parse.add_argument('-r', '--reli', choices=['sw', 'sr', 'gbn'], default="sw",
                       help='choose which method used for reliable transfer, '
                            'sw is stop wait, gbn is go back n, sr is selective repeat. default is sw')
    parse.add_argument('-w', '--window', type=valid_window, default=5,
                       help='window size used for reliable transfer, when using "go back n" or "selective repeat"'
                            'window size must be a positive integer, default is five')

    # parse the arguments
    return parse.parse_args()


# grab arguments from user
args = get_args()

# an instance of the application may only be server or client, this functions as a xor operator
if not (args.server ^ args.client):
    raise AttributeError("you must run either in server or client mode")


# starts a client version of the program, and sets up the DRTP in the requested reliable transfer method.
# also breaks the file into bytes to create packets from, and transfers those bytes as long as there are more to send
# first we must use send_hello to establish a connection and send information about our client.
# then after transferring the file we say goodbye.
def client():
    # sets method for reliable transfer.
    if args.reli == "gbn":
        method = DRTP.GoBackN(args.bind, args.serverip,
                              args.port, args.window, args.test)
    elif args.reli == 'sr':
        method = DRTP.SelectiveRepeat(args.bind, args.serverip,
                                      args.port, args.window, args.test)
    else:
        method = DRTP.StopWait(args.bind, args.serverip,
                               args.port, args.window, args.test)
    # binds UDP connection to local ipv4 address and port.
    method.bind_con()

    # let server know we are trying to connect,
    # the argument in send_hello is the filename we are going to attempt to transmit
    method.send_hello(args.file.split('/')[-1])
    if method.test:
        print(f"performing test: {method.test}")

    # grab the time we started sending packets
    time_start_sending = time.time()

    # send packets as long as there are parts to read and last sending was successful 
    # 'rb' is read, bytes so the file is opened and read as bytes, we read 1460 bytes at a time,
    # unless there aren't enough bytes left
    with open(args.file, 'rb') as fil:
        # if last sending wasn't succesfull we quit.
        send_succesfull = True
        chunk = fil.read(1460)
        # create first packet so that we don't send an extra empty packet.
        while chunk and send_succesfull:
            send_succesfull = method.send(chunk)
            chunk = fil.read(1460)

    # if we got this far and transfering bytes was a success, we send a last packet with the fin flag, else we quit.
    if send_succesfull:
        fil_size = os.path.getsize(args.file) / 1000
        method.send_fin()
        total_transfer_time = time.time() - time_start_sending
        str_total_time = "%.3fs" % total_transfer_time
        str_rate = "%.3fKB/s" % (fil_size/total_transfer_time)
        print(f"total transfer time: {str_total_time}\ntotal file size: {fil_size}KB\nacheived rate: {str_rate}")

    else:
        print("sending failed! exiting")
        sys.exit(1)


#
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
                # grab the time we received a packet
                header, body = DRTP.split_packet(data)

                # if header doesn't have syn flag, it's an old packet,
                # we send an ack to calm the client
                if not header.get_syn():
                    print(f"got an old header, sending an ack\n{header}")
                    header.set_acked(header.get_seqed())
                    header.set_ack(True)
                    header.set_fin(header.get_fin())
                    serv_sock.sendto(header.build_header(), addr)
                    serv_sock.close()
                    break

            except KeyboardInterrupt:
                print("Keyboard interrupt recieved, exiting server")
                sys.exit(1)

            # grab header and body from the packet.
            header, body = DRTP.split_packet(data)
            print(header)

            # if an old client is still attempting to send packets, there might be some issues
            try:
                # attempt to grab the information given by a connecting client.
                en_client = json.loads(body.decode())
            except UnicodeDecodeError:
                # close the socket, so it may be opened anew by the server loop
                serv_sock.close()
                print("wrong packet received, body is not a JSON! \nrestarting server")
                break
            except AttributeError:
                # close the socket, so it may be opened anew by the server loop
                serv_sock.close()
                print("wrong packet received, body is not a JSON! \nrestarting server")
                break

            # create a server version of the client attempting to connect,
            # we grab the -r, -f, w and t flag from the client. (reliable method, filename, window and test flag)
            if en_client['typ'] == 'GoBackN':
                remote_client = DRTP.GoBackN(args.bind, en_client['laddr'],
                                             args.port, en_client['window'], en_client['test'])
            elif en_client['typ'] == 'StopWait':
                remote_client = DRTP.StopWait(args.bind, en_client['laddr'],
                                              args.port, 1, en_client['test'])
            elif en_client['typ'] == 'SelectiveRepeat':
                remote_client = DRTP.SelectiveRepeat(args.bind, en_client['laddr'],
                                                     args.port, en_client['window'], en_client['test'])
            else:
                # quit if something unforeseen has happened
                print("client information insufficient, couldn't decide type of connecting client, exiting")
                serv_sock.close()
                break

            # hands over the received header from the connected client
            remote_client.remote_header = header

            # hands the socket over, for future transfers.
            remote_client.set_con(serv_sock)

            # tell user about what kind of test is to be run
            if remote_client.test:
                print(f"performing test: {remote_client.test}")

            print("\nmottat header")
            print(remote_client.remote_header)

            # start over if the remote client doesn't respond to our answer
            if remote_client.answer_hello():

                # make a 'fil' file in folder names 'ut'
                filnavn = en_client['fil']
                absolute = os.path.abspath(os.path.dirname(__file__))
                # go back to src folder
                absolute = absolute[:-4]
                # go to 'ut' folder
                path = absolute + f"/ut/{filnavn}"
                # if the filename exists, increment by 1 in the name
                unik_fil = get_save_file(path)
                # make an empty file
                print("making empty file at \n" + unik_fil)
                open(unik_fil, "x")

                # write to file as long as transmission isn't done and there is something in data.
                with open(unik_fil, "ab") as skriv:
                    data = remote_client.recv(1500)
                    while not remote_client.local_header.get_fin() and data:
                        skriv.write(data)
                        data = remote_client.recv(1500)

                # if we received a fin flag, we say goodbye
                if remote_client.remote_header.get_fin():
                    remote_client.answer_fin()
                    print(f"saving file at\n{unik_fil}")

                # we can infer that the transfer failed if we never got a fin flag,
                # in that case we remove the half transferred file.
                else:
                    print("removing failed file")
                    os.remove(path)

        # restarts server after an error occurs
        server()


if args.server:
    server()
else:
    client()
