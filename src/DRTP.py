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
        self.local_header = Header(bytearray(12))
        self.remote_header = Header(bytearray(12))
        self.con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def set_con(self, con):
        self.con = con

    def create_packet(self, data):
        header = self.local_header.build_header()
        packet = header + data
        print(f'packet containing header + data of size {len(packet)}')  # just to show the length of the packet
        return packet

    # a function used to send a establish a connection, from a client to a server.
    def send_hello(self, fil_name):
        self.local_header.set_syn(True)
        # set syn flag to 1
        # body is a json object, carrying information about the client.
        body = self.grab_json(fil_name).encode()
        packet = self.create_packet(body)
        print("sendt header")
        print(self.local_header)
        self.con.sendto(packet, (self.raddr, self.port))

        self.con.settimeout(5)

        # receive an ack from the server
        try:
            data, addr = self.con.recvfrom(500)
        except TimeoutError:
            print(f"Coulnd't establish a connection to {self.raddr}:{self.port}")
            sys.exit(1)

        # check the ack from the server
        self.remote_header, body = split_packet(data)
        print("mottat header")
        print(self.remote_header)

        if self.remote_header.get_ack() and self.remote_header.get_syn():
            self.local_header.increment_seqed()
            self.local_header.set_flags("0100")

            # send empty packet with the correct flags
            self.con.sendto(self.local_header.build_header(), (self.raddr, self.port))

    # a function to respond to the first connection from a client.
    def answer_hello(self):
        self.con.settimeout(5)
        # check that we have received the first header in the sequence and syn flag is set.
        if self.remote_header.get_syn() and not self.remote_header.get_seqed():
            # setter syn og ack flag i egen header.
            self.local_header.set_flags("1100")

            # lager en tom pakke
            # time.sleep(1)
            header = self.local_header.build_header()

            # answer the hello.
            print("sendt header")
            print(self.local_header)
            print(f"sender til {self.raddr, self.port}")
            self.con.sendto(header, (self.raddr, self.port))

        try:
            data, addr = self.con.recvfrom(500)
        except:
            print(f"couldn't establish connection with {self.raddr}:{self.port}")
            sys.exit(1)

        self.remote_header, body = split_packet(data)

        print(self.remote_header)
        # if self.remote_header.get_ack() and self.remote_header.get_seqed() == self.local_header.get_seqed():


# Det som mangler i A_con: Sende FIN header (si ha det)
# det som er ferdig foreløpig er at ein startar prorgammet.
# data sendes i chunks med forskjellig header - tanken er å lag ein header funksjon


class StopWait(A_Con):
    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 1

    def send(self, data):

        # lager pakke og sender den.
        pakke = self.create_packet(data)
        self.con.sendto(pakke, (self.raddr, self.port))

    def recv(self, chunk_size):
        if not self.local_header.get_seqed():
            self.answer_hello()

        data, addr = self.con.recvfrom(chunk_size)
        self.remote_header, body = split_packet(data)
        print("mottat header")
        print(self.remote_header)


# Må hente header fra Header, henter funksjoner for sending og mottaking av pakker fra A_Con
# vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

class GoBackN(A_Con):
    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 5

    # Må hente header fra Header, henter funksjoner for sending og mottaking av pakker fra A_Con
    # vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

    def send(self, data):
        if self.local_header.get_seqed() == 0:
            self.send_hello()


class SelectiveRepeat(A_Con):
    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 5

    # Må hente header fra Header, henter funksjoner for sending og mottaking av pakker fra A_Con
    # vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

    def send(self, data):
        if self.local_header.get_seqed() == 0:
            self.send_hello()


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
