This project consist of two programs, a modified version of simpleperf using UDP,
and a protocol called DRTP used to reliably transmit the packages.

A client transmits an image from the 'img' folder.
Then a copy of the image is stored at the server in a folder called 'ut'.
Both folders must be present on the computer running the program
and the python scripts has to be in the src folder.

The server transmits the image 'alle_dyr.png' in the img folder by default.
using stop and wait by default.
The method for reliable transfer is decided when running a client. There are three options when setting the -r flag.

    -r sr <Selective Repeat>    -r sw <Stop and Wait>   -r gbn <Go back n>
    
A server version of the program is invoked as follows, if the program is run in mininet, 
the program usually finds the local ipv4 address at that node:

    $ python3 simpleperf.py -s    (attempts to open a connection to local ipv4 address at port 8088)
    $ python3 simpleperf.by -s -b <ipv4_address> -p <port>

When a client connects, it will advertise the following to the server:

    the window size for the connection,
    the method for reliable transfer,
    the name of the file to be transfered,
    the artificial test to be run on either server or client.
    
the client version of the program decides what image to transfer with the '-f, --file' flag.
the method for reliable transfer may be decided with the '-r, --reli' flag.
A test can be performed on either server or client side, when invoking a client with the '-t, --test' flag,
no test is performed by default.
The user may decide the window size when starting a client aswell, with the '-w, --window' flag default is 5.
if not specified otherwise with the '-I, --serverip' flag, 
the client attempts to connect with node h3 if not otherwise specified.
the client can be invoked as follows:

    $ python3 simpleperf.py -c  (starts a connection to h3 at port 8088 and transmitt alle_dyr.png, with stop wait)
    $ python3 simpleperf.py -c -I <server_ip> -t <test_name> -f <file_in_img> -p <port> -r <method> -w <window_size>

There is also a help page in the program, if run as follows:

    $ python3 simpleperf.py -h

Will print a message to screen about what inputs are allowed and how they work. 

The available tests are skipack,skipseq,reorder and dupack, it's required that the file used when testing is more than 1460 bytes,
since all tests are run on the second packet, reordering also requires two packets to make any sense, 
reordering is therefore performed on the first available window, 
NOTE the specified window must be smaller than the requested file when using reorder or the test will fail


required filesystem to run the program:

    .
    ├── img
    │   ├── alle_dyr.png
    │   ├── kameleon.jpg
    │   └── sopp.jpg
    ├── src
    │   ├── DRTP.py
    │   └── simpleperf.py
    ├── topo.py
    └── ut
