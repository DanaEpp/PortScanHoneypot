# Port Scan Honeypot
This tool helps blue teams detect bad actors who may be port scanning the network, and allows red teams to practice honeypot evasion. 

#blueteam vs #redteam = #FTW

## Usage
```bash 
python3 -portscanhoneypot  
        [-c /path/to/config.conf] [-d] [--daemon]
```

* `-c`, `--config` [optional] : The location file of the YAML config (default is /etc/pshp.conf)
* `-d`, `--debug` [optional] : Enables debug logging
* `--daemon` [optional]: Run port scan detector in daemon mode

**NOTE:** Due to the fact this tool uses raw sockets you must run this as root. Have concerns with that? Consider putting it into docker a container.

**#blueteam TIP** : Don't monitor this on a lot of ports. Pick a few that are sensitive and indicators of compromise that you KNOW users shouldn't be scanning inside your network. And for gawds sake, don't hang this on the Internet, or thou shall be shodan spammed. You have been warned. ;-)

**#redteam TIP** : When considering honeypot evasion, #blueteams might run these types of detection tools in dedicated containers standalone. Watch for DNS and NETBIOS chatter.... consider avoiding scanning hosts that aren't interacting with other hosts... they might just be a honeypot.

**#bountyhunter TIP** : Be loud and proud. You are not trying to evade port scan detectors. If the host is in scope and allows for port scanning, then go to town. Light up #blueteam's logs and see if they contact you. :-)  