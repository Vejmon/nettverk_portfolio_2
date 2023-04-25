import socket
import sys
from struct import *

# header format is always the same, so a variable is here for convenience
header_format = '!IIHH'

#A_con Grunnklassen som har alt som er felles for de tre klassene
class A_Con:

    def __str__(self):
        return '{"laddr": "%s", "raddr": "%s", "port": %s, "typ": "%s"}' % \
            (self.laddr, self.raddr, self.port, type(self).__name__)

    def __init__(self, laddr, raddr, port):
        self.laddr = laddr
        self.raddr = raddr
        self.port = port
        self.seqed = 0
        self.acked = 0
        self.syn = 0
        self.ack = 0
        self.fin = 0
        self.win = 0
        self.con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #
    def set_connection(self, laddr, raddr, port):
        self.laddr = laddr
        self.raddr = raddr
        self.port = port

    def set_con(self, con):
        self.con = con

# fra safiqul
# creates a packet with header information and application data
# the input arguments are sequence number, acknowledgment number
# flags (we only use 4 bits),  receiver window and application data
# struct.pack returns a bytes object containing the header values
# packed according to the header_format !IIHH
    def split_packet(self, data):
        header = data[:12]
        body = False
        try:
            body = data[12:]
        except IndexError:
            print("ingen body")

        if body:
            return header, body
        else:
            return header, False

    def create_packet(self, data):

        header = pack(header_format, self.seqed, self.acked, self.insert_flags(), self.win)

        # once we create a header, we add the application data to create a packet
        # of 1472 bytes
        packet = header + data
        print(f'packet containing header + data of size {len(packet)}')  # just to show the length of the packet
        return packet

    # fra safiqul
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
        # the returned tuple is in this format
        # seq, ack, flags(syn,ack,fin,rst), win

    # fra safiqul
    def insert_flags(self):
        flags = str(self.syn) + str(self.ack) + str(self.fin) + "0"
        return int(flags)

    # fra safiqul
    def parse_flags(self, flags):
        # we only parse the first 3 fields because we're not
        # using rst in our implementation
        syn = flags & (1 << 3)
        ack = flags & (1 << 2)
        fin = flags & (1 << 1)
        return syn, ack, fin


    # a function used to send a syn message to a server from a client.
    def send_hello(self):
        # set syn flag to 1
        self.syn = 1
        # body is a json object, carrying information about the client.
        body = self.__str__().encode()
        packet = self.create_packet(body)
        self.con.sendto(packet, (self.raddr, self.port))

        self.con.settimeout(2.5)
        try:
            data, addr = self.con.recvfrom(500)
        except TimeoutError:
            print(f"Coulnd't establish a connection to {self.raddr}:{self.port}")
            sys.exit(1)

        header, body = self.split_packet(data)

        seqed, acked, flags, win = self.parse_header(header)
        syn, ack, fin = self.parse_flags(flags)


    def answer_hello(self, syn_header):
        seqed, acked, flags, win = self.parse_header(syn_header)
        syn, ack, fin = self.parse_flags(flags)




# Det som mangler i A_con: Sende FIN header (si ha det)
# det som er ferdig foreløpig er at ein startar prorgammet.
#data sendes i chunks med forskjellig header - tanken er å lag ein header funksjon


class StopWait(A_Con):

    def send(self, data):

        # if we are sending the first packet, we are establishing a connection first.
        if self.seqed == 0:
            self.send_hello()

        print(data)

    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 1

#Må hente header fra a_con
#vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

class GoBackN(A_Con):

    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 5
#Må hente header fra a_con
#vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

    def send(self, data):
        if self.seqed == 0:
            self.send_hello()

class SelectiveRepeat(A_Con):
    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 5
#Må hente header fra a_con
#vil ha særgen funksjonalitet, f. eks. når det gjelder ACK

    def send(self, data):
        if self.seqed == 0:
            self.send_hello()