#!/usr/bin/env python3
from enum import IntEnum
import logging
import requests
import json
import pymsteams

username="honeypot"

class WebHookType(IntEnum):
    NONE = 0
    GENERIC = 1
    SLACK = 2
    TEAMS = 3
    DISCORD = 4

class WebHook:
    DEFAULT_HEADERS = {'Content-Type': 'application/json'}

    def __init__(self, url, hooktype=WebHookType.GENERIC):
        self.url = url
        self.hooktype = hooktype
        
    def notify(self, message):
        if message:
            # Why oh why can't python support switch/case??? >:( 
            if self.hooktype == WebHookType.GENERIC:
                self.__send_to_generic_webhook(message)
            elif self.hooktype == WebHookType.SLACK:
                self.__send_to_slack(message)
            elif self.hooktype == WebHookType.TEAMS:
                self.__send_to_teams(message)
            elif self.hooktype == WebHookType.DISCORD:
                self.__send_to_discord(message)

    def __send_to_generic_webhook(self, message):
        logging.debug( "[WEBHOOK] {0}".format(message))

        data = {
            'content': message,
            'username': username
        }

        try:
            response = requests.post( self.url, data=json.dumps(data), headers=WebHook.DEFAULT_HEADERS)
            if not response.ok:
                logging.debug( "Failed to send notification via Generic webhook. Server response: {0}".format(response.text))
        except Exception as e:
            logging.exception(e)
        
    # See https://api.slack.com/messaging/webhooks for more info
    def __send_to_slack(self, message):
        logging.debug( "[SLACK] {0}".format(message))

        # Remember to set your webhook up at https://my.slack.com/services/new/incoming-webhook/
        data = {
            'text': message,
            'username': 'Port Scan Honeypot',
            'icon_emoji': ':skull_and_crossbones:'
        }

        try:
            response = requests.post( self.url, data=json.dumps(data), headers=WebHook.DEFAULT_HEADERS)
            if not response.ok:
                logging.debug( "Failed to send notification via Slack. Server response: {0}".format(response.text))
        except Exception as e:            
            logging.exception(e)

    # See https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook
    def __send_to_teams(self, message):
        logging.debug( "[TEAMS] {0}".format(message))
         
        try:
            teams = pymsteams.connectorcard(self.url)
            teams.title( "&#x2620 Port scan detected!")
            teams.text(message)
            teams.send()
        except Exception as e:
            logging.exception(e)
    
    def __send_to_discord(self, message):
        logging.debug( "[DISCORD] {0}".format(message))

        data = {
            'content': message,
            'username': username
        }

        try:
            response = requests.post( self.url, data=json.dumps(data), headers=WebHook.DEFAULT_HEADERS)
            if not response.ok:
                logging.debug( "Failed to send notification via Discord. Server response: {0}".format(response.text))

        except Exception as e:
            logging.exception(e)
