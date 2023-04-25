import os.path
import socket
import sys
from struct import *
import random

# header format is always the same, so a variable is here for convenience
header_format = '!IIHH'


# A_con Grunnklassen som har alt som er felles for de tre klassene
class A_Con:
    def __str__(self):
        return '{"laddr": "%s", "raddr": "%s", "port": %s, "typ": "%s"}' % \
            (self.laddr, self.raddr, self.port, type(self).__name__)

    def __init__(self, laddr, raddr, port):
        self.laddr = laddr
        self.raddr = raddr
        self.port = port
        self.local_header = Header(bytearray(12))
        self.remote_header = Header(bytearray(12))
        self.con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def set_con(self, con):
        self.con = con

    def split_packet(self, data):
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


    def create_packet(self, data):
        header = self.local_header.build_header()
        packet = header + data
        print(f'packet containing header + data of size {len(packet)}')  # just to show the length of the packet
        return packet

    # a function used to send a establish a connection, from a client to a server.
    def send_hello(self):
        self.local_header.syn = 1
        # set syn flag to 1
        # body is a json object, carrying information about the client.
        body = self.__str__().encode()

        packet = self.create_packet(body)
        self.con.sendto(packet, (self.raddr, self.port))
        self.con.settimeout(2.5)
        # receive an ack from the server
        try:
            data, addr = self.con.recvfrom(500)
        except TimeoutError:
            print(f"Coulnd't establish a connection to {self.raddr}:{self.port}")
            sys.exit(1)

        # check the ack from the server
        header_data , body = self.split_packet(data)
        self.remote_header = Header(header_data)
        if self.remote_header.get_ack() and self.remote_header.get_syn:

            self.local_header.increment_seq()
            self.local_header.set_flags("0100")

            self.con.sendto(self.create_packet(b'0'), (self.raddr, self.port))

    # a function to respond to the first connection from a client.
    def answer_hello(self, syn_header):
        header = Header(syn_header)




# Det som mangler i A_con: Sende FIN header (si ha det)
# det som er ferdig foreløpig er at ein startar prorgammet.
# data sendes i chunks med forskjellig header - tanken er å lag ein header funksjon


class StopWait(A_Con):
    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 1

    def send(self, data):
        # if we are sending the first packet, we are establishing a connection first.
        if not self.local_header.get_seqed():
            self.send_hello()

        print(data)

    def recv(self, chunks):

        # lager en random random fil i ut mappen
        abs = os.path.dirname(__file__)
        hash = random.getrandbits(128)
        path = abs + f"/../ut/{hash}"

        # skriv til filen så lenge fin flagget ikke er satt
        while not self.local_header.get_fin():
            data, addr = self.con.recvfrom(chunks)
            with open(path, "w") as skriv:
                skriv.write(chunks)


# Må hente header fra a_con
# vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

class GoBackN(A_Con):
    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 5

    # Må hente header fra a_con
    # vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

    def send(self, data):
        if self.local_header.get_seqed() == 0:
            self.send_hello()


class SelectiveRepeat(A_Con):
    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 5

    # Må hente header fra a_con
    # vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

    def send(self, data):
        if self.local_header.get_seqed() == 0:
            self.send_hello()

class Header:
    def __init__(self, header):
        self.seqed, self.acked, self.flags, self.win = self.parse_header(header)
        self.syn, self.ack, self.fin = self.parse_flags(self.flags)

    def increment_seq(self):
        self.seqed += 1

    def parse_flags(self, integer_4bit):
        integer = int(integer_4bit)
        syn = integer & (1 << 3)
        ack = integer & (1 << 2)
        fin = integer & (1 << 1)
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

    def get_seqed(self):
        return self.seqed

    def get_acked(self):
        return self.acked

    def set_flags(self, integer_4bit):
        integer = int(integer_4bit)
        self.syn = integer & (1 << 3)
        self.ack = integer & (1 << 2)
        self.fin = integer & (1 << 1)

    def get_flags(self):
        flags = str(self.syn) + str(self.ack) + str(self.fin) + "0"
        return int(flags)

    def set_ack(self, one_or_zero):
        self.ack = one_or_zero

    def get_ack(self):
        return self.ack

    def set_win(self, integer):
        self.win = integer

    def get_win(self):
        return self.win

    def set_fin(self, one_or_zero):
        self.fin = one_or_zero

    def get_fin(self):
        return self.fin

    def get_syn(self):
        return self.syn

    def set_syn(self, one_or_zero):
        self.syn = one_or_zero