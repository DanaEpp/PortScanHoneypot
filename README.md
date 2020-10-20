# Port Scan Honeypot
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=pshp-github&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=pshp-github)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=pshp-github&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=pshp-github)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=pshp-github&metric=security_rating)](https://sonarcloud.io/dashboard?id=pshp-github)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=pshp-github&metric=alert_status)](https://sonarcloud.io/dashboard?id=pshp-github)

[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=pshp-github&metric=bugs)](https://sonarcloud.io/dashboard?id=pshp-github)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=pshp-github&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=pshp-github)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=pshp-github&metric=code_smells)](https://sonarcloud.io/dashboard?id=pshp-github)

This tool helps blue teams detect bad actors who may be port scanning the network, and allows red teams to practice honeypot evasion. 

#blueteam vs #redteam = #FTW

## Usage
```bash 
python3 portscanhoneypot  
        [-c /path/to/config.conf] [-d] [--daemon]
```

* `-c`, `--config` [optional] : The location file of the YAML config (default is /etc/pshp.conf)
* `-d`, `--debug` [optional] : Enables debug logging
* `--daemon` [optional]: Run port scan detector in daemon mode

**NOTE:** Due to the fact this tool uses raw sockets you must run this as root. Have concerns with that? Consider putting it into docker a container.

**#blueteam TIP** : Don't monitor this on a lot of ports. Pick a few that are sensitive and indicators of compromise that you KNOW users shouldn't be scanning inside your network. And for gawds sake, don't hang this on the Internet, or thou shall be shodan spammed. You have been warned. ;-)

**#redteam TIP** : When considering honeypot evasion, #blueteams might run these types of detection tools in dedicated containers standalone. Watch for DNS and NETBIOS chatter.... consider avoiding scanning hosts that aren't interacting with other hosts... they might just be a honeypot.

**#bugbountyhunter TIP** : Be loud and proud. You are not trying to evade port scan detectors. If the host is in scope and allows for port scanning, then go to town. Light up #blueteam's logs and see if they contact you. :-) 

## Webhooks support
To assist in notifying your team when port scans are detected consider using webhook notifications.

You can configure your webhooks in the `pshp.conf` file:

```
webhook_url: "https://your.url/to/your/webhook"
webhook_type: 0
```

You can set `webhook_type` to any of the following numbers:
* 0 : NONE
* 1 : GENERIC
* 2 : SLACK
* 3 : MS TEAMS
* 4 : DISCORD

For more information on setting up webhook notifications for your favorite apps please see:
* **Slack** : [Detailed instructions](https://api.slack.com/messaging/webhooks). To setup your first one [go here](https://my.slack.com/services/new/incoming-webhook/).
* **Microsoft Teams** : [Detailed instructions](https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)
* **Discord** : [Detailed instructions](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks)

### Working with generic webhooks like Microsoft Logic Apps
If you are wanting to get notifications to a different device or email, consider using the "generic" webhook option and configure it to point to a [Microsoft Logic App](https://azure.microsoft.com/en-us/services/logic-apps/). When defining the HTTP receive endpoint in Azure use the following Request Body JSON Schema:

```
{
    "properties": {
        "content": {
            "type": "string"
        },
        "username": {
            "type": "string"
        }
    },
    "type": "object"
}
```

By defining it in that way, the Logic App will parse out the payload and allow direct dynamic content variables for use in your workflow. From there you can do anything with the payload, from sending it via SMS to your phone or directly to email.

Have fun with it. Generic webhooks and Logic Apps can do some pretty powerful things.
