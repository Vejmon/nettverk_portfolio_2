This project consist of two programs, a modified version of simpleperf using UDP,
and a protocol called DRTP used to reliably transmit the packages.

A client transmits an image the 'img' folder.
Then a copy of the image is stored at the server in a folder called 'ut'.

the server transmits the image kameleon.jpg in the img folder by default.
using stop and wait by default.

The method for reliable transfer is decided when running a client. There are three options when setting the -r flag.

    -r sr <Selective Repeat>    -r sw <Stop and Wait>   -r gbn <Go back n>
    

A server version of the program is invoked as follows, if the program is run in mininet, 
the program usually finds the local ipv4 address at that node:

    $ python3 simpleperf.py -s
    $ python3 simpleperf.by -s -b <ipv4_address> -p <port>

When a client connects, it will advertise the following to the server:

    the window size for the connection,
    the method for reliable transfer,
    the name of the file to be transfered,
    the artificial test to be run on either server or client.
    

the client version of the program decides what image to transfer with the '-f, --file flag'
the method for reliable transfer may be decided with the '-r, --reli' flag.
Lastly the test to be ran on either the client or the server may be decided when runnning a client with the '-t, --test' flag
By default the client attempts to connect with node h3 if not otherwise specified.
the client can be invoked as follows:

    $ python3 simpleperf.py -c  <starts a connection to h3 and transmitt kameleon.jpg, with stop wait>
    $ python3 simpleperf.py -c -I <server_ip> -t <test_name> -f <file_in_img> -p <port> -r <method> -w <window_size>

we've attempted to build the DRTP protocol so that the usage in simpleperf is closely mimicking a TCP socket.
