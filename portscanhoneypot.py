#!/bin/env python3
"""
portscanhoneypot:   

Simple honeypot to catch rogue port scans on the network for use as an early warning
beacon of potential threat actors on the network.

Author: Dana Epp (@danaepp)

"""
import os
import os.path
import sys
import getopt
import socket
import threading
import time
from struct import unpack, pack
import logging
from appsettings import AppSettings
from webhooks import WebHook, WebHookType

# Colors
# --------------
RED = '\33[31m'
CYAN = '\33[36m'
GREEN = '\33[32m'
WHITE = '\33[0m'
# --------------

# Ethernet Header Length
ETH_HEADER_LEN = 14

# TCP control flags
TH_FIN = 0x01  # end of data
TH_SYN = 0x02  # synchronize sequence numbers
TH_RST = 0x04  # reset connection
TH_PSH = 0x08  # push
TH_ACK = 0x10  # acknowledgment number set
TH_URG = 0x20  # urgent pointer set
TH_ECE = 0x40  # ECN echo, RFC 3168
TH_CWR = 0x80  # congestion window reduced

# Generic timestamp for local logging
get_timestamp = lambda : time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

# Versioning
__version__ = "1.0"
PIDFILE="/var/run/pshp.pid"


class PortScanHoneyPot:

    def __init__(self, settings, loglevel=None):
        PortScanHoneyPot.setup_logging(loglevel)
        self.__daemon = settings.daemon
        self.__iface = settings.iface
        self.__listening_ips = settings.listening_ips
        self.__listening_ports = settings.listening_ports
        self.__allowed_hosts = settings.allowed_hosts
        self.__logfile = settings.portscanlog

        # Setup optional webhook for notifications
        if settings.webhook and settings.webhook_type != WebHookType.NONE :
            self.__webhook = WebHook(settings.webhook, settings.webhook_type)
        else:
            self.__webhook = None            

    @classmethod
    def print_banner(cls):
        print(f"\n{CYAN}==================================================")
        print(f" {WHITE}PortScan Honeypot{CYAN} ({WHITE}v{__version__}{CYAN}) - Developed by @danaepp")
        print(f" https://github.com/danaepp/PortScanHoneypot")
        print(f"=================================================={WHITE} \n")

    @classmethod
    def display_usage(cls):
        print( 'sudo portscanhoneypot.py\n\t[-c /path/to/config.conf] [-d] [--daemon]\n' )       
        
    @classmethod
    def setup_logging(cls, log_level):
        if log_level is None:
            logging.basicConfig( 
                stream=sys.stdout, 
                level=log_level,
                format='%(asctime)s [%(levelname)s] %(message)s',
                datefmt='%m/%d/%Y %I:%M:%S %p' )
        else:
            logging.basicConfig( 
                filename="pshp_debug.log", 
                level=log_level,
                format='%(asctime)s [%(levelname)s] %(message)s',
                datefmt='%m/%d/%Y %I:%M:%S %p' )

    def write_log(self, line):
        if self.__logfile:
            self.__logfile.write( f"{line}\n")
            self.__logfile.flush()

    def process_packet(self, packet, addr):

        # Get Ethernet frame header        
        eth_header = packet[:ETH_HEADER_LEN]

        # Break out the ethernet frame
        eth = unpack('!6s6sH' , eth_header)

        # Get the protocol. We only want to deal with IP packets (8)
        eth_protocol = socket.ntohs( eth[2] )

        if eth_protocol == 8:
            # Parse IP header
            #     0                   1                   2                   3
            #     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            #    |Version|  IHL  |Type of Service|          Total Length         |
            #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            #    |         Identification        |Flags|      Fragment Offset    |
            #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            #    |  Time to Live |    Protocol   |         Header Checksum       |
            #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            #    |                       Source Address                          |
            #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            #    |                    Destination Address                        |
            #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            #    |                    Options                    |    Padding    |
            #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            ip_header = packet[ETH_HEADER_LEN:20 + ETH_HEADER_LEN]

            # Unpack the header
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            # Need to calc IP header size for use later
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4

            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            # Only look for TCP connections (6)
            if protocol == 6:
                # Parse TCP header
                #     0                   1                   2                   3
                #     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                #    |          Source Port          |       Destination Port        |
                #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                #    |                        Sequence Number                        |
                #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                #    |                    Acknowledgment Number                      |
                #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                #    |  Data |           |U|A|P|R|S|F|                               |
                #    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
                #    |       |           |G|K|H|T|N|N|                               |
                #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                #    |           Checksum            |         Urgent Pointer        |
                #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                #    |                    Options                    |    Padding    |
                #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                #    |                             data                              |
                #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                t = iph_length + ETH_HEADER_LEN
                
                # Extract raw bytes of TCP header
                tcp_header = packet[t:t+20]

                # Unpack TCP header
                tcph = unpack('!HHLLBBHHH' , tcp_header)                
                dest_port = tcph[1]
                flags = tcph[5]

                # We only want to monitor the interface IP for the listening ports... 
                # drop everything else
                if d_addr in self.__listening_ips and dest_port in self.__listening_ports:
                    self.__process_scanner_packet(flags, s_addr, d_addr, dest_port)

    # Process scanner packets tripped up by the honeypot
    def __process_scanner_packet(self, flags, s_addr, d_addr, d_port):
        # We want to make sure we drop packets from allowed hosts (ie: RMM/NM/Network scanners etc)
        if s_addr not in self.__allowed_hosts:
            scan_type = self.get_scan_type(flags)
            flags_str = self.get_flags(flags)
            msg = f"[{get_timestamp()}] {scan_type} scan (flags:{flags_str}) detected from {str(s_addr)} to {str(d_addr)}:{str(d_port)}"
            self.write_log(msg)

            if self.__webhook:
                self.__webhook.notify(msg)

            if not self.__daemon:
                print( msg )

    def get_scan_type(self, flags):
        # TCP flags to scan type mapping
        scan_types_mapping = {
            0: 'TCP NULL',
            TH_FIN: 'TCP FIN',
            TH_SYN: 'TCP SYN', 
            TH_SYN|TH_RST: 'TCP SYN',
            TH_ACK: 'TCP ACK',
            TH_URG|TH_PSH|TH_FIN: 'TCP XMAS', 
            TH_URG|TH_PSH|TH_FIN|TH_ACK: 'TCP XMAS',
            TH_SYN|TH_FIN: 'TCP SYN/FIN',
            TH_FIN|TH_ACK: 'TCP FIN/ACK',
            TH_SYN|TH_ACK|TH_RST: 'TCP CONN',
            TH_URG|TH_PSH|TH_ACK|TH_RST|TH_SYN|TH_FIN: 'TCP ALL-FLAGS' 
        } 

        return scan_types_mapping.get(flags, 'unknown')

    def get_flags(self, flags):
        flags_str = ''

        if flags == 0:
            flags_str = 'N'
        else:
            if flags & TH_URG:
                flags_str += 'U'
            if flags & TH_ACK:
                flags_str += 'A'
            if flags & TH_PSH:
                flags_str += 'P'
            if flags & TH_RST:
                flags_str += 'R'
            if flags & TH_SYN:
                flags_str += 'S'
            if flags & TH_FIN:
                flags_str += 'F'

        return flags_str

    def sniff(self):
        print( f"Starting up honeypot to detect port scans on '{self.__iface}'..." )

        try:
            sock = socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3) )  # 3 = ETH_P_ALL
        except Exception as err:
            # Should only hit here if raw sockets aren't allowed
            logging.exception(err)
            sys.exit()

        try:
            sock.bind((self.__iface, 0))
        except OSError as err:            
            logging.exception(err)
            sys.exit("Bind failed. Aborting.")
        except Exception as ex:
            logging.exception(ex)
            sys.exit("General exception while binding. Aborting")

        while True:
            try:
                packet, addr = sock.recvfrom(65535)
                threading.Thread(target=self.process_packet, args=(packet, addr)).start()       
            except KeyboardInterrupt:
                if not self.__logfile.closed:
                    self.__logfile.close()
                sys.exit()
            except Exception as ex:
                print( "General exception while listening for port scans." )
                logging.exception(ex)

    def run(self):
        if self.__daemon:
            # Disconnect from tty
            try:
                pid = os.fork()
                if pid>0:
                    sys.exit(0)
            except OSError as e:
                logging.exception(e)
                sys.exit("First fork failed during daemonize")

            os.setsid()
            os.umask(0)

            # We need a second fork to fully disconnect the process
            try:
                pid = os.fork()
                if pid>0:
                    open(PIDFILE,'w').write(str(pid))
                    sys.exit(0)
            except OSError as e:
                logging.exception(e)
                sys.exit("Second fork failed during daemonize")

            # If we get this far, we now have a disconnected daemon process and we can sniff
            logging.info( "Launching Port Scan Honeypot as a daemon..." )
            self.sniff()
        else:
            self.print_banner()
            self.sniff()

def main(argv):

    if os.geteuid() != 0:
        msg = "You must have effective 'root' privs to run this program"
        logging.error(msg)
        sys.exit(msg)

    settingsfile = None
    loglevel = None
    daemon = False

    try:
        opts, args = getopt.getopt( argv, 
            "hc:d", 
            ["help", "config=", "debug", "daemon"])
    except getopt.GetoptError as err:
        logging.exception(err)
        sys.exit(2)

    for opt, arg in opts:
        if opt in ( "-h", "--help"):
            PortScanHoneyPot.display_usage()
            sys.exit()
        elif opt in ( "-c", "--config" ):
            settingsfile = arg
        elif opt in ( "-d", "--debug" ):
            loglevel = logging.DEBUG
        elif opt in ( "--daemon" ):
            daemon = True

    settings = AppSettings(daemon, settingsfile)
    honey_pot = PortScanHoneyPot(settings, loglevel)
    honey_pot.run()

if __name__ == "__main__":
    main(sys.argv[1:])
