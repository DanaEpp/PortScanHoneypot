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

        self.iface = 'lo'
        self.listening_ips = []
        self.listening_ports = []
        self.allowed_hosts = []
        self.daemon = daemon

        if settingsfile is None:
            settingsfile = '/etc/pshp.conf'

        # Check to see if we have a config file to work with
        if os.path.isfile(settingsfile):
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

                self.iface = self.__assign_value( settings, "iface", "eth0" )
                self.listening_ports = self.__assign_value( settings, "ports", [8080] )
                self.allowed_hosts = self.__assign_value( settings, "allowed_hosts", [] )

                if 'webhook_url' in settings:
                    url = settings['webhook_url']

                    # If there is a bad URL, just drop webhook support
                    if validators.url(url):
                        self.webhook = url
                        self.webhook_type = self.__assign_value( settings, "webhook_type", WebHookType.GENERIC )
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

    def __assign_value(self, settings, key, default_val ):                
        if key in settings:
            val = settings[key]
        else:
            logging.warning( f"'{key}' settings missing from config. Using defaults.")
            val = default_val
        return val

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
