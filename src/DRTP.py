from struct import *


class A_Con:
    def __init__(self, laddr, lport, raddr, rport):
        self.laddr = laddr
        self.lport = lport
        self.raddr = raddr
        self.rport = rport
        self.type = type
        self.seq = 0
        self.ack = 0
        self.syn = 0
        self.form = '!IIHH'


    def create_packet(self, flags, data):
        # creates a packet with header information and application data
        # the input arguments are sequence number, acknowledgment number
        # flags (we only use 4 bits),  receiver window and application data
        # struct.pack returns a bytes object containing the header values
        # packed according to the header_format !IIHH
        header = pack(self.form, self.seq, self.ack, flags, data)


        # once we create a header, we add the application data to create a packet
        # of 1472 bytes
        packet = header + data
        print(f'packet containing header + data of size {len(packet)}')  # just to show the length of the packet
        return packet

    def parse_header(header):
        # taks a header of 12 bytes as an argument,
        # unpacks the value based on the specified header_format
        # and return a tuple with the values
        header_from_msg = unpack(header_format, header)
        # parse_flags(flags)
        return header_from_msg

    def parse_flags(flags):
        # we only parse the first 3 fields because we're not
        # using rst in our implementation
        syn = flags & (1 << 3)
        ack = flags & (1 << 2)
        fin = flags & (1 << 1)
        return syn, ack, fin

    # now let's create a packet with sequence number 1


class StartStop(A_Con):
    def __init__(self, laddr, lport, raddr, rport):
        super().__init__(laddr, lport, raddr, rport)
        self.window = 1

