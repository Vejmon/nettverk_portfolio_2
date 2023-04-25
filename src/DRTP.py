from struct import *
header_format = '!IIHH'


class A_Con:

    def __str__(self):
        return '{"laddr": "%s", "raddr": "%s", "port": %s, "typ": "%s"}' % \
            (self.laddr, self.raddr, self.port, type(self).__name__)

    def __init__(self, laddr, raddr, port):
        self.laddr = laddr
        self.raddr = raddr
        self.port = port
        self.seq = 0
        self.acked = 0
        self.syn = 0
        self.ack = 0
        self.fin = 0
        self.win = 0

    #
    def set_connection(self, laddr, raddr, port):
        self.laddr = laddr
        self.raddr = raddr
        self.port = port

# fra safiqul
# creates a packet with header information and application data
# the input arguments are sequence number, acknowledgment number
# flags (we only use 4 bits),  receiver window and application data
# struct.pack returns a bytes object containing the header values
# packed according to the header_format !IIHH
    def create_packet(self, flags, data):
        header = pack(self.form, self.seq, self.ack, flags, data)

        # once we create a header, we add the application data to create a packet
        # of 1472 bytes
        packet = header + data
        print(f'packet containing header + data of size {len(packet)}')  # just to show the length of the packet
        return packet

    # fra safiqul
    def parse_header(header):
        # taks a header of 12 bytes as an argument,
        # unpacks the value based on the specified header_format
        # and return a tuple with the values
        header_from_msg = unpack(header_format, header)
        # parse_flags(flags)
        return header_from_msg

    # fra safiqul
    def insert_flags(self):
        flags = str(self.syn) + str(self.ack) + str(self.fin) + "0"
        return int(flags)

    # fra safiqul
    def parse_flags(flags):
        # we only parse the first 3 fields because we're not
        # using rst in our implementation
        syn = flags & (1 << 3)
        ack = flags & (1 << 2)
        fin = flags & (1 << 1)
        return syn, ack, fin


    # a function used to send a syn message to a server from a client.
    def send_hello(self, con):

        self.syn = 1
        header = pack(header_format, self.seq, self.ack, self.insert_flags(), self.win)

        # is a json object, carrying information about the connecting client.
        body = self.__str__().encode()

        con.sendto(header + body, (self.raddr, self.port))
        self.syn = 0

# Det som mangler i A_con: Sende FIN header (si ha det)
# det som er ferdig foreløpig er at ein startar prorgammet.
#data sendes i chunks med forskjellig header - tanken er å lag ein header funksjon


class StopWait(A_Con):
    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 1


class GoBackN(A_Con):
    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 5


class SelectiveRepeat(A_Con):
    def __init__(self, laddr, raddr, port):
        super().__init__(laddr, raddr, port)
        self.window = 5
