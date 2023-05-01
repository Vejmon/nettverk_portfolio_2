import socket
import sys
import time
from struct import *

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

        self.local_header.set_syn(True)
        # this procedure is only for the first syn_message
        # set syn flag to 1
        # body is a json object, carrying information about the client.
        body = self.grab_json(fil_name).encode()
        packet = self.create_packet(body)

        print("sendt header")
        print(self.local_header)

        # attempt four times to start a connection
        self.con.sendto(packet, (self.raddr, self.port))

        self.con.settimeout(self.timeout)

        # wait for a response from the server
        try:
            data, addr = self.con.recvfrom(500)
        except TimeoutError:
            print(f"Couldn't establish a connection to {self.raddr}:{self.port}")
            sys.exit(1)

        # grab the header from the response packet
        self.remote_header, body = split_packet(data)
        print("mottat header")
        print(self.remote_header)

        # check if ack flag, and syn flag are set, from response
        if self.remote_header.get_ack() and self.remote_header.get_syn():
            # set only ack flag in next header.
            self.local_header.set_flags("0100")

            # send empty packet with the ack_flag. before transmitting data.
            print("siste svar: sendt header")
            print(self.local_header)
            self.con.sendto(self.local_header.build_header(), (self.raddr, self.port))
            # set alle flag til 0
            self.local_header.set_flags("0000")
        else:
            print("Header from server has insuficient data!")

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

            # attempt to transmit an answer four times.
            counter = 0
            while counter < 4:
                self.con.sendto(packet, (self.raddr, self.port))
                try:
                    data, addr = self.con.recvfrom(500)
                    break
                except TimeoutError:
                    counter += 1

            # gir opp hvis vi har prøvd 4 ganger.
            if counter == 3:
                print(f'unable to establish connection with {self.raddr}:{self.port}')
                return False

            # grab header from received packet
            self.remote_header, body = split_packet(data)

            print("mottat header")
            print(self.remote_header)

            if self.remote_header.get_ack():
                # increment secked and acked, and set only ack flag for future responses
                self.local_header.set_flags("0100")

                print("lokal pakke ser slik ut!")
                print(self.local_header.__str__())
                return True

        # gir opp hvis flagg fra client ikke er satt riktig.
        else:
            return False

    def send_fin(self):

        # build a last packet with fin flag set
        self.local_header.set_fin(True)
        self.local_header.increment_seqed()
        self.con.settimeout(self.timeout)
        # send packet untill we get the "fin_ack"
        for i in range(6):
            print("sending fin_packet")
            self.con.sendto(self.local_header.build_header(), (self.raddr, self.port))

            try:
                data, addr = self.con.recvfrom(50)
                self.remote_header, body = split_packet(data)
                # if we got the next header in sequence with a syn flag set we are done
                if self.client_compare_headers() and self.remote_header.get_fin():
                    self.con.close()
                    print("fin_ack received, quitting")
                    return
            except socket.timeout:
                print("didn't receive fin_ack, attempting again")

            except TimeoutError:
                print("didn't receive fin_ack, attempting again")

        print("never got a fin_ack, giving up")

    def answer_fin(self):

        print("sending fin_ack")
        self.local_header.set_fin(True)
        self.con.sendto(self.local_header.build_header(), (self.raddr, self.port))

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
        if self.remote_header.get_ack() and self.remote_header.get_acked() == self.remote_header.get_seqed():
            print("godkjent")
            return True

        print("sjekk headers Client!")
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
                    self.local_header.increment_both()
                    pakke = self.local_header.complete_packet()
                    self.con.sendto(pakke, (self.raddr, self.port))
                    return body
                else:
                    # resend old ack
                    self.con.sendto(self.local_header.complete_packet(), (self.raddr, self.port))

            except socket.timeout:
                print("prøver igjen")

            except TimeoutError:
                print("prøver igjen")

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
        if self.remote_header.get_ack() and self.remote_header.get_acked() == self.local_header.get_seqed():
            print("godkjent")
            return True

        print("sjekk headers Client!")
        return False


    def __init__(self, laddr, raddr, port, window):
        super().__init__(laddr, raddr, port, window)
        self.window = window
        self.timeout = 3
        self.local_buffer = [None] * self.window
        self.next_seq_num = 1
        self.send_base = 1
        self.list_local_headers = []
        self.list_remote_headers = []
        self.list_acked_or_seqed = []


    # Må hente header fra Header, henter funksjoner for sending og mottaking av pakker fra A_Con
    # vil ha særgen funksjonalitet, f. eks. når det gjelder ACK


    def recv_acks(self):

        self.con.settimeout(self.timeout)
        # receive packets and compare them with the list of sendt packets.
        for packet in self.list_local_headers:

            try:    # receive acks from server
                data, addr = self.con.recvfrom(12)
                header, body = split_packet(data)
                self.remote_header = header

            except socket.timeout:
                print("didn't receive ack")
            except TimeoutError:
                print("didn't receive ack")

            self.local_header = packet
            self.local_header.set_acked(self.remote_header.get_acked())


            # if we got wrong ack, delete correctly acked packets, and break loop
            if not self.client_compare_headers():

                index = self.list_local_headers.index(packet)
                # remove packets before last incorrectly received packet
                del self.list_local_headers[0:index]
                for packet in self.list_local_headers:
                    packet.set_acked(self.remote_header.get_acked())
                # break out of loop to send new batch of packets.
                return False

        return True

    def send(self, data):

        # set seq and create a packet with data ready to be sent.
        self.local_header.increment_seqed()
        a_packet = HeaderWithBody(self.local_header.build_header(), data)

        # append the packet to list of outgoing packets
        self.list_local_headers.append(a_packet)

        # if we are not sending the fin flag, and list is smaller than window we return to add more packets.
        if not self.local_header.get_fin() and len(self.list_local_headers) < self.window:
            return True

        # send all the packets in order.
        print("sending packets:\n")
        for packet in self.list_local_headers:
            print(packet)
            self.con.sendto(packet.complete_packet(), (self.raddr, self.port))

        # receive acks from server.
        if self.recv_acks():
            self.list_local_headers.clear()

        return True




    """    # Increase seq-number
        self.local_header.increment_seqed()
        # Create a packet body from the data
        self.local_header.body = data
        # Create packet
        packet = self.local_header.complete_packet()

        # Store packet in local buffer
        self.local_buffer[self.next_seq_num % self.window] = packet

        # Send packets within window without waiting for ACK for each packet
        while self.next_seq_num < self.send_base + self.window:
            # Send packet
            self.con.sendto(packet, (self.raddr, self.port))

            # If all packets in window have sent, set timeout for ACK
            if self.send_base == self.next_seq_num:
                self.con.settimeout(self.timeout)

            # Increase sequence number
            self.next_seq_num += 1

        # Receive ACKs
        while True:
            try:
                data, addr = self.con.recvfrom(12)
                self.remote_header, body = split_packet(data)

                # If ACK is invalid, discard
                if not self.client_compare_headers():
                    continue

                # Update send_base
                self.send_base = self.next_seq_num + 1

                # Reset timeout if all packets have been ACKed
                if self.send_base == self.next_seq_num:
                    self.con.settimeout(None)

            except socket.timeout:
                # Retransmit all packets starting from the last ACKed packet
                for i in range(self.send_base, self.next_seq_num):
                    self.con.sendto(self.local_buffer[i % self.window], (self.raddr, self.port))

                    # Set timeout for ACK
                    self.con.settimeout(self.timeout)

                    """

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
                    self.local_header.increment_both()
                    pakke = self.local_header.complete_packet()
                    self.con.sendto(pakke, (self.raddr, self.port))
                    return body
                else:
                    # resend old ack
                    self.con.sendto(self.local_header.complete_packet(), (self.raddr, self.port))

            except socket.timeout:
                print("prøver igjen")

            except TimeoutError:
                print("prøver igjen")

        return None


class SelectiveRepeat(A_Con):
    def __init__(self, laddr, raddr, port, window):
        super().__init__(laddr, raddr, port, window)
        self.window = window
        self.list_local_packets = []
        self.list_remote_acks = []

    # Må hente header fra Header, henter funksjoner for sending og mottaking av pakker fra A_Con
    # vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

    def send_fin(self):

        self.local_header.set_fin(True)
        # send fin header, with a batch of packets
        self.send(b'')



    def resend_non_acked(self):

        for a_packet in self.list_local_packets:
            # compare see if seqed nr is in list of acks

            # if packet in list of acked, update header_acked
            if a_packet.get_seqed() in self.list_remote_acks:
                a_packet.set_acked(a_packet.get_seqed)
            else:
                # if packet is not in list of acked, resend that packet
                print("\nre-sending packet")
                print(a_packet)
                self.con.sendto(a_packet.complete_packet(), (self.raddr, self.port))

    def client_receive_acks(self):
        counter = 0
        while len(self.list_remote_acks) < len(self.list_local_packets):
            # attempt to receive acks from server
            try:
                an_ack = self.con.recvfrom(50)
                header, body = split_packet(an_ack)
                print("received packet:\n" + header.__str__())
                ack_nr = header.get_acked()

                # update last remote header
                if ack_nr > self.remote_header.get_acked():
                    self.remote_header = header
                """# check if ack_nr already in list of acks
                # then we got a duplicated ack
                if ack_nr in self.list_remote_acks:
                    self.resend_non_acked()"""

                # put acked from server in list of acked packets.
                self.list_remote_acks.append(ack_nr)
                # break from inner loop if packet received successfully


            except socket.timeout:
                counter += 1
                print("sending lost packets")
                self.resend_non_acked()

            except TimeoutError:
                counter += 1
                print("sending lost packets")
                self.resend_non_acked()

            print(counter)
            # if we have attempted more than three times we quit
            if counter > 3:
                return False

        return True

    def send(self, data):
        # IMPORTANT
        # fin_packet is also sent in a batch of packets
        # can't use a_con's send_fin()

        # recursively add packets to list of outgoing packets
        # until list of packets is as big as window size.

        if len(self.list_local_packets) < self.window:
            self.local_header.increment_seqed()
            a_packet = HeaderWithBody(self.local_header.complete_packet(), data)
            self.list_local_packets.append(a_packet)

            # if fin flag is set, we don't need to add more packets.
            if not self.local_header.get_fin():
                return True

        # send all packets
        for packet in self.list_local_packets:
            print("sending packet:\n" + packet.__str__())
            self.con.sendto(packet.complete_packet(), (self.raddr, self.port))

        # receive acks from server
        self.con.settimeout(self.timeout)
        while True:

            # break outer loop if list of acks is full
            if len(self.list_local_packets) == len(self.list_remote_acks):
                break
            # attempt to receive acks
            if not self.client_receive_acks():
                return False


        if len(self.list_local_packets) == len(self.list_remote_acks):
            # update last sendt header
            # remote header is updated in client_receive acks
            self.local_header = self.list_local_packets[-1]

            # clear lists for a new batch of packets.
            self.list_remote_acks.clear()
            self.list_local_packets.clear()

    def send_acks(self):
        # send acks for received packets
        for received_packet in self.list_local_packets:
            self.con.sendto(received_packet.complete_packet(), (self.raddr, self.port))

    def recv(self, chunk_size):
        self.con.settimeout(self.timeout)

        # ack last batch again, if client didn't get acks
        if len(self.list_local_packets) != 0:

            try:
                data, addr = self.con.recvfrom(chunk_size)
                header, body = split_packet(data)
                a_packet = HeaderWithBody(header.build_header(), body)



            except socket.timeout:
                print("hmmmm")
            except TimeoutError:
                print("hmm")

        fant_fin = False
        while len(self.list_local_packets) < self.window and not fant_fin:
        # receive a packet
            try:
                data, addr = self.con.recvfrom(chunk_size)
                header, body = split_packet(data)
                a_packet = HeaderWithBody(header.build_header(), body)
                print("packet received\n" + a_packet.__str__())

                a_packet.set_acked(a_packet.get_seqed())
                a_packet.set_ack(True)          # set the ack flag to true
                self.list_remote_acks.append(a_packet.get_acked())
                self.list_local_packets.append(a_packet)

                # sort the lists
                sorted(self.list_remote_acks)
                self.list_local_packets.sort(key=lambda x: x.seqed)


            except TimeoutError:
                self.send_acks()

            except socket.timeout:
                self.send_acks()
                print("didn't receive packet")

        # send acks and return full body of bytes
        full_body = b''
        for packet in self.list_local_packets:
            print(packet)
            self.con.sendto(packet.build_header(), (self.raddr, self.port))
            full_body += packet.body

        return full_body

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
