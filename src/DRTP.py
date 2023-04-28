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
        return '{"laddr": "%s", "raddr": "%s", "port": %s, "typ": "%s", "fil": "%s"}' % \
            (self.laddr, self.raddr, self.port, type(self).__name__, file_name)

    def __str__(self):
        return '{"laddr": "%s", "raddr": "%s", "port": %s, "typ": "%s"}' % \
            (self.laddr, self.raddr, self.port, type(self).__name__)

    def __init__(self, laddr, raddr, port):
        self.laddr = laddr
        self.raddr = raddr
        self.port = port
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

        self.con.settimeout(2)

        # wait for a response from the server
        try:
            data, addr = self.con.recvfrom(500)
        except TimeoutError:
            print(f"Coulnd't establish a connection to {self.raddr}:{self.port}")
            sys.exit(1)

        # grab the header from the response packet
        self.remote_header, body = split_packet(data)
        print("mottat ack fra server header")
        print(self.remote_header)

        # check if ack flag, and syn flag are set, from response
        if self.remote_header.get_ack() and self.remote_header.get_syn():
            # increment acked og seqed, in next header
            self.local_header.increment_both()
            # set only ack flag in next header.
            self.local_header.set_flags("0100")

            # send empty packet with the ack_flag. before transmitting data.
            print("siste svar: sendt header")
            print(self.local_header)

            self.con.sendto(self.local_header.build_header(), (self.raddr, self.port))
            # set alle flag til 0 på client
            self.local_header.set_flags("0000")

            # set previous_packet to the one we sent now.
            self.previous_packet = self.local_header
        else:
            print("Header from server has insuficient data!")

    # a function to respond to the first connection from a client.

    def answer_hello(self):
        # set wait timeout, set to rtt in future fix fix
        self.con.settimeout(2)

        # check that and syn flag is set in first packet.
        if self.remote_header.get_syn():

            # copy sequence and nr of acked from remote header
            self.local_header.set_acked(self.remote_header.get_acked())
            self.local_header.set_seqed(self.remote_header.get_seqed())

            # setter syn and ack in response header.
            self.local_header.set_flags("1100")

            # create empty packet
            packet = self.create_packet(None)

            # attempt to transmit an answer four times.
            print("første ack til server")
            print(self.local_header)

            counter = 0
            while counter < 4:
                self.con.sendto(packet, (self.raddr, self.port))
                try:
                    data, addr = self.con.recvfrom(500)
                    # grab header from received packet
                    self.remote_header, body = split_packet(data)

                    # break out of loop if successfully received packet
                    break
                except TimeoutError:
                    counter += 1

            # give up establishing connection after four tries.
            if counter == 3:
                print(f'unable to establish connection with {self.raddr}:{self.port}')
                return False

            print("mottat siste ack fra client header")
            print(self.remote_header)

            counter = 0
            while counter < 4:
                if self.remote_header.get_ack() and self.remote_header.get_acked():

                    # increment secked and acked, and set only ack flag for future responses
                    self.local_header.set_flags("0100")
                    self.local_header.increment_both()

                    print("lokal pakke ser slik ut!")
                    print(self.local_header.__str__())
                    return True

                # gir opp hvis flagg fra client ikke er satt riktig.
                else:
                    self.con.sendto(self.local_header.build_header(), (self.raddr, self.port))
                    counter += 1

            print("server gir opp")
            return False

    def server_compare_headers(self):
        print("\nremote header")
        print(self.remote_header)
        print("local header")
        print(self.local_header.__str__() + "\n")

        if not self.remote_header.get_ack() and self.local_header.get_seqed() == self.remote_header.get_seqed() - 1:
            if self.remote_header.get_acked() == self.local_header.get_acked():
                print("godkjent")

                # save old header before incrementing
                self.previous_packet = self.local_header
                self.local_header.increment_both()

        print("sjekk headers")
        return False

    def client_compare_headers(self):
        print("\nremote header")
        print(self.remote_header)
        print("local header")
        print(self.local_header.__str__() + "\n")

        if self.remote_header.get_ack() and self.remote_header.get_seqed() == self.local_header.get_seqed():
            if self.remote_header.get_acked() == self.local_header.get_acked() - 1:
                print("godkjent")
                self.previous_packet = self.local_header
                self.local_header.increment_both()
                return True

        print("sjekk headers!")
        return False


# Det som mangler i A_con: Sende FIN header (si ha det)
# det som er ferdig foreløpig er at ein startar prorgammet.
# data sendes i chunks med forskjellig header - tanken er å lag ein header funksjon


class StopWait(A_Con):

    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 1
        self.local_header = HeaderWithBody(bytearray(12), None)
        self.remote_header = HeaderWithBody(bytearray(12), None)

    def send(self, data):
        packet = self.create_packet(data)

        # attempt four times to send a packet containing bytes with data
        counter = 0
        while counter < 4:
            self.con.sendto(packet, (self.raddr, self.port))

            # send the new packet, until we get a negative ack
            try:
                data, addr = self.con.recvfrom(500)

                # if we recieve a packet but it's not the ack we want
                # we transfer the old packet
                self.remote_header, body = split_packet(data)
                if self.client_compare_headers():
                    # if the packed is acked the old packet is saved, and a new local packet is sequenced and acked
                    return True
                else:
                    packet = self.previous_packet.complete_packet()
            except TimeoutError:
                counter += 1

        # tranfer failed.
        return False

    def recv(self, chunk_size):

        # ack for a new chunk
        packet = self.local_header.build_header()
        counter = 0
        # attempt to receive a chunk of bytes, and ack that chunk.
        while counter < 4:
            try:
                data, addr = self.con.recvfrom(chunk_size)
                self.remote_header, body = split_packet(data)

                # if it's wrong packet, we sand ack for old packet
                # else we return chunk
                if self.server_compare_headers():
                    return body
                else:
                    packet = self.previous_packet.build_header()

            except TimeoutError:
                self.con.sendto(packet, (self.raddr, self.port))
                counter += 1

        return None


# Må hente header fra Header, henter funksjoner for sending og mottaking av pakker fra A_Con
# vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

class GoBackN(A_Con):
    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 5

    def lists_of_headers(self):
        sendt_packets = []
        recvd_packets = []

        for i in range(self.window):
            sendt_packets.append(HeaderWithBody(bytearray(12), None))
            recvd_packets.append(HeaderWithBody(bytearray(12), None))

    # Må hente header fra Header, henter funksjoner for sending og mottaking av pakker fra A_Con
    # vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

    def send(self, data):
        print("send_hello(filnavn) først!")


class SelectiveRepeat(A_Con):
    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 5

    # Må hente header fra Header, henter funksjoner for sending og mottaking av pakker fra A_Con
    # vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

    def send(self, data):
        print("send_hello(filnavn) først")


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
