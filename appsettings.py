import os
import socket
import fcntl
from struct import pack, unpack
import logging
import yaml
from webhooks import WebHookType, WebHook
import validators

class AppSettings:
    def __init__(self, daemon=False, settingsfile='/etc/pshp.conf', logfile='/var/log/pshp.log'):

        self.listening_ips = []
        self.daemon = daemon

        # Check to see if we have a config file to work with
        if settingsfile != None and os.path.isfile(settingsfile):
            self.__load_settings(settingsfile)
        else:
            msg = "Valid config file not detected. Using defaults."
            logging.warning(msg)
            self.__set_defaults()

        listening_ip = self.__get_ip_address(self.iface)
        self.listening_ips.append( listening_ip )        

        try:
            self.portscanlog = open(logfile,'a')
        except Exception as err:
            print( f"Error opening portscan log file '{logfile}'. Err: {err}")
            self.portscanlog = None

    def __load_settings(self, settingsfile):
        with open(settingsfile, 'r') as stream:
            try:
                settings = yaml.safe_load(stream)

                if 'iface' in settings:
                    self.iface = settings['iface']
                else:
                    logging.warning( "'iface' settings missing from config. Using defaults.")
                    self.iface = 'eth0'

                if 'ports' in settings:
                    self.listening_ports = settings['ports']
                else:
                    logging.warning( "'ports' settings missing from config. Using defaults.")
                    self.listening_ports = [8080]

                if 'webhook_url' in settings:
                    url = settings['webhook_url']

                    # If there is a bad URL, just drop webhook support
                    if validators.url(url):
                        self.webhook = url
                        if 'webhook_type' in settings:
                            self.webhook_type = settings['webhook_type']
                        else:
                            self.webhook_type = WebHookType.GENERIC
                    else:
                        logging.warning( "Bad webhook URL. Disabling webhook support." )
                        self.webhook = None
                        self.webhook_type = WebHookType.NONE
                else:
                    self.webhook = None
                    self.webhook_type = WebHookType.NONE
            except yaml.YAMLError as exc:
                logging.exception(exc)
                self.__set_defaults()

    def __set_defaults(self):
        self.iface = 'eth0'
        self.listening_ports = [8080]
        self.webhook = None
        self.webhook_type = WebHookType.NONE

    def __get_ip_address(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            pack('256s', bytes(ifname[:15], 'utf-8'))
        )[20:24])
