import socket
import sys
import time
from struct import *
# eh
# header format is always the same, so a variable is here for convenience
header_format = '!IIHH'


def split_packet(data):
    header_data = data[:12]
    body = False
    try:
        body = data[12:]
    except IndexError:
        print("ingen body")
    remote_header = Header(header_data)

    if body:
        return remote_header, body
    else:
        return remote_header, False


# A_con Grunnklassen som har alt som er felles for de tre klassene
class A_Con:

    # used to transmit a JSON object to server, letting server know about the client's -r and -f flag.
    # fix let server know about -t flag aswell?
    def grab_json(self, file_name):
        return '{"laddr": "%s", "raddr": "%s", "port": %s, "typ": "%s", "fil": "%s", "window": %s}' % \
            (self.laddr, self.raddr, self.port, type(self).__name__, file_name, self.window)

    def __str__(self):
        return '{"laddr": "%s", "raddr": "%s", "port": %s, "typ": "%s"}' % \
            (self.laddr, self.raddr, self.port, type(self).__name__)

    def __init__(self, laddr, raddr, port, window):
        self.laddr = laddr
        self.raddr = raddr
        self.port = port
        self.window = window
        self.timeout = 2
        self.previous_packet = HeaderWithBody(bytearray(12), None)  # previous packet sent from client
        self.local_header = HeaderWithBody(bytearray(12), None)  # header we are attempting to send now
        self.remote_header = Header(bytearray(12))  # response header from server
        self.con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # connection we are attempting to transmit over

    # loop at server hands over connection
    def set_con(self, con):
        self.con = con
        return

    # bind a UDP (SOCK_DGRAM) socket to local ipv4_address (AF_INET) and port.
    def bind_con(self):
        self.con.bind((self.laddr, self.port))

    # appends body to end of local_header
    # body must be byte object
    def create_packet(self, data):
        packet = self.local_header.build_header()
        if data:
            packet = packet + data
        # print(f'packet containing header + data of size {len(packet)}')  # just to show the length of the packet
        return packet

    # a function used to send a establish a connection, from a client to a server.
    def send_hello(self, fil_name):
        # this procedure is only for the first syn_message
        # set syn flag to 1
        self.local_header.set_syn(True)

        # body is a json object, carrying information about the client.
        # fil_name is used to let the server know the name of the file to ba transferred
        body = self.grab_json(fil_name).encode()
        packet = self.create_packet(body)

        self.con.settimeout(self.timeout)
        counter = 0
        # attempt multiple times to start a connection
        while True:
            print("\nsending hello:")
            print(self.local_header)

            self.con.sendto(packet, (self.raddr, self.port))
            # wait for a response from the server
            try:
                data, addr = self.con.recvfrom(12)
                # break out of loop if we got anything
                self.remote_header, body = split_packet(data)
                if self.remote_header.get_ack() and self.remote_header.get_syn():
                    break
            except TimeoutError:
                counter += 1
                print(f"didn't receive ack from server at: {self.raddr}:{self.port}")

            if counter == 9:
                print("couldn't establish connection, giving up")
                sys.exit()

        # grab the header from the response packet
        print("\ngot ack from server:")
        print(self.remote_header)

        # set up response to the server.
        # set only ack flag in next header.
        self.local_header.set_flags("0100")

        # send empty packet with the ack_flag. before transmitting data.
        print("\nsiste ack fra client:")
        print(self.local_header)
        self.con.sendto(self.local_header.build_header(), (self.raddr, self.port))
        # set alle flag til 0
        self.local_header.set_flags("0000")


    # a function to respond to the first connection from a client.
    def answer_hello(self):
        # set wait timeout, set to rtt in future fix fix
        self.con.settimeout(self.timeout)

        # check that and syn flag is set in first packet.
        if self.remote_header.get_syn():

            # copy sequence and nr of acked from remote header
            self.local_header.set_acked(self.remote_header.get_acked())
            self.local_header.set_seqed(self.remote_header.get_seqed())

            # setter syn og ack flag i egen header.
            self.local_header.set_flags("1100")

            print("sendt header")
            print(self.local_header)
            # create empty packet
            packet = self.create_packet(None)

            # set empty data to silence warning
            data = b''

            # attempt to transmit an answer.
            counter = 0
            while True:
                self.con.sendto(packet, (self.raddr, self.port))

                try:
                    data, addr = self.con.recvfrom(500)
                    self.remote_header, body = split_packet(data)

                    # if we receive a syn packet again, respond again!
                    if self.remote_header.get_syn():
                        print("got a syn packet, resending")

                    elif self.remote_header.get_ack():
                        print("got an ack ready to receive packets")
                        break

                    elif body:
                        print("got first packet")
                        break

                except TimeoutError:
                    print("timed out, resending")

                counter += 1
                # gir opp hvis vi har prøvd mange.
                if counter > 9:
                    print(f'unable to establish connection with {self.raddr}:{self.port}')
                    return False

            print(self.remote_header)
            self.local_header.set_flags("0100")
            return True

    def send_fin(self):

        # build a last packet with fin flag set
        self.local_header.set_fin(True)
        self.local_header.increment_seqed()
        self.con.settimeout(self.timeout)
        # send packet untill we get the "fin_ack"
        for i in range(6):

            self.con.sendto(self.local_header.build_header(), (self.raddr, self.port))
            try:
                data, addr = self.con.recvfrom(50)
                self.remote_header, body = split_packet(data)
                # if we got the next header in sequence with a syn flag set we are done
                if self.client_compare_headers() and self.remote_header.get_fin():
                    self.con.close()
                    print(f"fin_ack received!\nquitting")

                    return
            except socket.timeout:
                print("didn't receive fin_ack, attempting again")

            except TimeoutError:
                print("didn't receive fin_ack, attempting again")

        print("never got a fin_ack, giving up")

    def answer_fin(self):

        print("sending fin_ack:\n" + self.local_header.__str__())
        for i in range(5):
            self.con.sendto(self.local_header.build_header(), (self.raddr, self.port))

    def server_compare_headers(self):
        print("\nremote header")
        print(self.remote_header.__str__())
        print("local header")
        print(self.local_header.__str__())

        # check if the packet is on the next sequence, and that the old packet has been acked.
        if self.remote_header.get_ack():
            print("fikk siste ack")
            return False

        if self.remote_header.get_seqed() == self.local_header.get_acked() + 1:
            print("godkjent\n")
            return True

        print("sjekk headers Server\n")
        return False

    def client_compare_headers(self):
        print("\nremote header")
        print(self.remote_header.__str__())
        print("local header")
        print(self.local_header.__str__())

        # if the remote header is on the same sequence, and has acked the packet, we move on
        if self.remote_header.get_ack() and self.remote_header.get_acked() == self.remote_header.get_seqed():
            print("godkjent\n")
            return True

        print("sjekk headers Client!\n")
        return False


# Det som mangler i A_con: Sende FIN header (si ha det)
# det som er ferdig foreløpig er at ein startar prorgammet.
# data sendes i chunks med forskjellig header - tanken er å lag ein header funksjon


class StopWait(A_Con):

    def __init__(self, laddr, raddr, port, window):
        super().__init__(laddr, raddr, port, window)
        self.window = 1
        self.local_header = HeaderWithBody(bytearray(12), None)
        self.remote_header = HeaderWithBody(bytearray(12), None)

    # Send data, receive ack: Client side
    def send(self, data):

        self.local_header.increment_seqed()
        self.local_header.body = data
        pakke = self.local_header.complete_packet()

        # Try to send the packet 6 times
        for i in range(6):

            self.con.settimeout(self.timeout)  # Set timeout for resending packet
            self.con.sendto(pakke, (self.raddr, self.port))

            try:
                remote_data, addr = self.con.recvfrom(50)
                self.remote_header, body = split_packet(remote_data)
                if self.client_compare_headers():  # Sjekker at ack flagget er satt og at acked = seqed
                    self.local_header.increment_acked()  # Øker ack number
                    return True

            except TimeoutError:
                print("prøver igjen")
            except socket.timeout:
                print("prøver igjen")

        return False

    # Receive data, send ack: Server side
    def recv(self, chunk_size):
        # Timeout
        self.con.settimeout(self.timeout)

        # recieve packets untill we have the one we are looking for.
        # quit if we never receive a packet.
        for i in range(6):
            try:
                data, addr = self.con.recvfrom(chunk_size)
                self.remote_header, body = split_packet(data)
                # if we got the correct packet, we increment our header, and return the data.
                if self.server_compare_headers():
                    # increase seqed and acked
                    self.local_header.increment_both()
                    # copy fin flag from client
                    self.local_header.set_fin(self.remote_header.get_fin())

                    # send ack of new packet
                    self.con.sendto(self.local_header.complete_packet(), (self.raddr, self.port))
                    return body
                else:
                    # resend old ack
                    print("resending old ack:\n" + self.local_header.__str__())
                    self.con.sendto(self.local_header.complete_packet(), (self.raddr, self.port))

            except TimeoutError:
                print("resending old ack:\n" + self.local_header.__str__())
                self.con.sendto(self.local_header.complete_packet(), (self.raddr, self.port))

        return None


# Må hente header fra Header, henter funksjoner for sending og mottaking av pakker fra A_Con
# vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

class GoBackN(A_Con):

    def server_compare_headers(self):
        print("\nremote header")
        print(self.remote_header.__str__())
        print("local header")
        print(self.local_header.__str__() + "\n")

        # check if the packet is on the next sequence, and that the old packet has been acked.
        if self.remote_header.get_seqed() == self.local_header.get_acked() + 1:
            print("godkjent")
            return True

        print("sjekk headers Server")
        return False

    def client_compare_headers(self):
        print("\nremote header")
        print(self.remote_header.__str__())
        print("local header")
        print(self.local_header.__str__() + "\n")

        # if the remote header is on the same sequence, and has acked the packet, we move on
        if self.remote_header.get_ack() and self.remote_header.get_acked() >= self.local_header.get_seqed():
            self.local_header.set_acked(self.remote_header.get_acked())
            print("godkjent")
            return True

        print("sjekk headers Client!")
        return False


    def __init__(self, laddr, raddr, port, window):
        super().__init__(laddr, raddr, port, window)
        self.window = window
        self.timeout = 1
        self.list_local_headers = []
        self.list_remote_headers = []


    # Må hente header fra Header, henter funksjoner for sending og mottaking av pakker fra A_Con
    # vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

    def recv_acks(self):

        self.con.settimeout(self.timeout)
        # receive packets if we timeout we stop receiving and look at what we got.
        for packet in self.list_local_headers:
            try:    # receive acks from server
                data, addr = self.con.recvfrom(12)
                header, body = split_packet(data)
                self.list_remote_headers.append(header)
            except TimeoutError:
                print("dropped one or more ack packet(s)")
                break

        # grab largest ack from list of received packets
        largest_ack = 0
        print("\nreceived packets:")
        for packet in self.list_remote_headers:
            print(packet)
            if packet.get_acked() > largest_ack:
                largest_ack = packet.get_acked()

        self.list_remote_headers.clear()
        print(f"\nbiggest ack received: {largest_ack}")

        # find index of item "behind" last acked packet
        index = 0
        for pkt in self.list_local_headers:
            index += 1
            if pkt.get_seqed() == largest_ack:
                break

        # remove packets before last incorrectly received packet
        del self.list_local_headers[0:index]

        # set last acked in remaining packets
        for packet in self.list_local_headers:
            packet.set_acked(largest_ack)
            print(packet)

        # set local header seqed back to first in list:
        self.local_header.set_acked(largest_ack)

        # break out of loop to send new batch of packets.
        if len(self.list_local_headers) == 0:
            return True
        else:
            return False


    def send_fin(self):
        # set fin flag in local header
        self.local_header.set_fin(True)
        # add empty packet to
        self.send(b'')

        try:
            data, addr = self.con.recvfrom(12)
            header, body = split_packet(data)
            print(f"fin_ack:\n{header}")
        except TimeoutError:
            print("didn't receive fin_ack:\nquitting")


    def send(self, data):

        # set seq and create a packet with data ready to be sent.
        self.local_header.increment_seqed()
        a_packet = HeaderWithBody(self.local_header.build_header(), data)

        # append the packet to list of outgoing packets
        self.list_local_headers.append(a_packet)

        # if we are not sending the fin flag, and list is smaller than window we return to add more packets.
        if not self.local_header.get_fin() and len(self.list_local_headers) < self.window:
            return True

        # attempt to send and receive acks, if no acks are present four times we give up.
        attempt_counter = 0

        while True:
            last_list_size = len(self.list_local_headers)
            # if all packets are acked, we are done with this batch
            if not last_list_size:
                return True
            # send all the packets in order.
            print("\nsending packets:")
            for packet in self.list_local_headers:
                print(packet)
                self.con.sendto(packet.complete_packet(), (self.raddr, self.port))
            # attempt to receive acks also trims away acked, packets
            self.recv_acks()

            if len(self.list_local_headers) == 0:
                return True
            # if list of packets remains the same we try again
            if len(self.list_local_headers) == last_list_size:
                attempt_counter += 1

            # if list is smaller than window, and we don't have the fin flag set in last item we want more packets
            if len(self.list_local_headers) < self.window and \
                not self.list_local_headers[len(self.list_local_headers) - 1].get_fin():
                return True

            # if we receive no acks in four attempts, we quit
            if attempt_counter == 4:
                return False



    def recv(self, chunk_size):
        # Timeout
        self.con.settimeout(self.timeout)

        # recieve packets untill we have the one we are looking for.
        # quit if we never receive a packet.
        for i in range(6):
            try:
                data, addr = self.con.recvfrom(chunk_size)
                self.remote_header, body = split_packet(data)
                # if we got the correct packet, we increment our header, and return an ack.
                if self.server_compare_headers():

                    self.local_header.set_fin(self.remote_header.get_fin())
                    self.local_header.increment_both()

                    self.con.sendto(self.local_header.complete_packet(), (self.raddr, self.port))
                    return body
                else:
                    # resend old ack
                    self.con.sendto(self.local_header.complete_packet(), (self.raddr, self.port))

            except TimeoutError:
                self.con.sendto(self.local_header.complete_packet(), (self.raddr, self.port))
                print("prøver igjen")

        return None


class SelectiveRepeat(A_Con):
    def __init__(self, laddr, raddr, port, window):
        super().__init__(laddr, raddr, port, window)
        self.window = window

        self.list_local_headers = []
        self.list_remote_acked_seqed = []
        self.list_remote_headers = []

    # Må hente header fra Header, henter funksjoner for sending og mottaking av pakker fra A_Con
    # vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

    def send_fin(self):
        self.local_header.set_fin(True)
        # send fin header, with a batch of packets
        self.send(b'')


    def recv_acks(self):
        self.con.settimeout(self.timeout)
        # receive packets if we time out we stop receiving and look at what we got.
        for packet in self.list_local_headers:
            # receive acks from server
            try:
                data, addr = self.con.recvfrom(12)
                header, body = split_packet(data)       #add the ack number to a list.
                self.list_remote_acked_seqed.append(header.get_acked())

            except TimeoutError:
                print("dropped one or more ack packet(s)")
                break

        # remove the acked packets from list of packets to send.
        print("\nreceived acks:")
        for pkt in self.list_local_headers:
            if pkt.get_seqed() in self.list_remote_acked_seqed:
                # increment number of acked packets
                self.local_header.increment_acked()
                print(pkt.get_seqed())

        # if the list is empty return True
        if not len(self.list_local_headers):
            return True
        else:
            return False

    def send(self, data):
        # IMPORTANT
        # fin_packet is also sent in a batch of packets
        # can't use a_con's send_fin()

        # set seq and create a packet with data ready to be sent.
        self.local_header.increment_seqed()

        a_packet = HeaderWithBody(self.local_header.build_header(), data)

        # append the packet to list of outgoing packets
        self.list_local_headers.append(a_packet)

        # if we are not sending the fin flag, and list is smaller than window we return to add more packets.
        if not self.local_header.get_fin() and len(self.list_local_headers) < self.window:
            return True

        # attempt to send and receive acks, if no acks are present four times we give up.
        attempt_counter = 0
        while True:

            # send all the packets in order.
            print("\nsending packets:")
            for packet in self.list_local_headers:
                print(packet)
                self.con.sendto(packet.complete_packet(), (self.raddr, self.port))
            # attempt to receive acks also trims away acked, packets
            if self.recv_acks():
                # if all packets are acked, we clear the lists, and add more packets
                self.list_remote_acked_seqed.clear()
                self.list_local_headers.clear()
                return True

            attempt_counter += 1
            # if we receive no acks, we quit
            if attempt_counter == 9:
                return False

    def send_acks(self):
        # send acks for received packets
        for pkt in self.list_local_headers:
            self.con.sendto(pkt.complete_packet(), (self.raddr, self.port))

    def recv(self, chunk_size):


        self.con.settimeout(self.timeout)
        last_acked = self.local_header.get_acked()

        """# build a list of expected packets
        expected_seqed = []
        for i in range(self.window):
            expected_seqed.append(last_acked + (i+1))"""
        print(self.window)
        for i in range(self.window):
            try:
                data, addr = self.con.recvfrom(chunk_size)
                header, body = split_packet(data)

                # if header has seqed = 0, then it's part of the handshake
                if header.get_seqed() not in self.list_remote_acked_seqed:
                    self.list_remote_acked_seqed.append(header.get_seqed())
                    # add header with body to list
                    self.list_remote_headers.append(HeaderWithBody(header.build_header(), body))

                    # add an ack to list of acks.
                    ack_packet = Header(bytearray(12))
                    ack_packet.set_ack(True)
                    ack_packet.set_seqed(self.remote_header.get_seqed())
                    ack_packet.set_acked(self.remote_header.get_seqed())
                    self.list_local_headers.append(ack_packet)

                    # respond with an ack for this spesific packet
                    self.con.sendto(ack_packet.build_header(), (self.raddr, self.port))

                    print("\nreceived packets:")
                    for pkt in self.list_remote_headers:
                        print(pkt)

            except TimeoutError:
                print("dropped a packet")
                print("responding with ack packets")
                for pkt in self.list_local_headers:
                    self.con.sendto(pkt.build_header(), (self.raddr, self.port))

            # sort the list of remote headers with by seqed and in increasing order
            sorted(self.list_remote_headers, key=lambda Header: Header.seqed)

            # if we got a full list, we stop to respond with some acks.

            # if we got a full window we send ack for all, and move on to next window.
            # or a not full window, but we got every step, and last step has a fin flag.
            every_step = True
            found_fin = False
            for i in range(len(self.list_remote_headers)):
                if self.list_remote_headers[i].get_fin():
                    found_fin = True

                if self.list_remote_headers[i].get_seqed() != (last_acked + i):
                    every_step = False

            if every_step and len(self.list_remote_headers) == self.window:
                total_bytes = b''
                for pkt in self.list_remote_headers:
                    total_bytes += pkt.body
                return total_bytes

            if every_step and found_fin:
                self.remote_header.set_fin(True)
                total_bytes = b''
                for pkt in self.list_remote_headers:
                    total_bytes += pkt.body
                return total_bytes

        # grab largest seq
        self.local_header.set_acked(max(self.list_remote_headers, key=lambda Header: Header.seqed))
        # receive packets while list of packets are smaller than window


class Header:
    def __str__(self):
        return '{"seqed": %s, "acked": %s, "syn": %s, "ack": %s, "fin": %s, "win": %s}' % \
            (self.seqed, self.acked, self.syn, self.ack, self.fin, self.win)

    def __init__(self, header):
        self.seqed, self.acked, self.flags, self.win = self.parse_header(header)
        self.syn, self.ack, self.fin = self.parse_flags(self.flags)

    # hacky løsning, liker ikke dette, fix fix
    def parse_flags(self, integer_4bit):
        integer_4bit = str(integer_4bit)
        if len(integer_4bit) < 4:
            integer_4bit = "000" + integer_4bit
        # print("inn: " + str(integer_4bit))
        syn = int(integer_4bit[-4])
        ack = int(integer_4bit[-3])
        fin = int(integer_4bit[-2])
        # print(f"ut: {syn}{ack}{fin}0")
        return syn, ack, fin

    def parse_header(self, header):
        # takes a header of 12 bytes as an argument,
        # unpacks the value based on the specified header_format
        # and return a tuple with the values
        header_from_msg = unpack(header_format, header)
        seqed = header_from_msg[0]
        acked = header_from_msg[1]
        flags = header_from_msg[2]
        win = header_from_msg[3]
        return seqed, acked, flags, win

    def build_header(self):
        return pack(header_format, self.seqed, self.acked, self.get_flags(), self.win)

    def set_flags(self, integer_4bit):
        integer_4bit = str(integer_4bit)
        if len(integer_4bit) < 4:
            integer_4bit = "000" + integer_4bit
        # print("inn: " + str(integer_4bit))
        self.syn = int(integer_4bit[-4])
        self.ack = int(integer_4bit[-3])
        self.fin = int(integer_4bit[-2])

    def get_flags(self):
        flags = str(self.syn) + str(self.ack) + str(self.fin) + "0"
        return int(flags)

    """
    bare uinteressante getter/setter under her!
    """

    def increment_both(self):
        self.seqed += 1
        self.acked += 1

    def increment_seqed(self):
        self.seqed += 1

    def set_seqed(self, seqed):
        self.seqed = seqed

    def get_seqed(self):
        return self.seqed

    def increment_acked(self):
        self.acked += 1

    def set_acked(self, acked):
        self.acked = acked

    def get_acked(self):
        return self.acked

    def set_ack(self, one_or_zero):
        if one_or_zero:
            self.ack = 1
        else:
            self.ack = 0

    def get_ack(self):
        return self.ack

    def set_win(self, integer):
        self.win = integer

    def get_win(self):
        return self.win

    def set_fin(self, one_or_zero):
        if one_or_zero:
            self.fin = 1
        else:
            self.fin = 0

    def get_fin(self):
        return self.fin

    def get_syn(self):
        return self.syn

    def set_syn(self, one_or_zero):
        if one_or_zero:
            self.syn = 1
        else:
            self.syn = 0


class HeaderWithBody(Header):
    def __init__(self, header, body):
        super().__init__(header)
        self.body = body

    def complete_packet(self):
        if self.body:
            return self.build_header() + self.body
        else:
            return self.build_header()
