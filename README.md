# Generate XSS Payloads from Common Sources

This is a simple script that attempts to simply generate XSS payloads from common sources. This script does not dynamically generate payloads based with sinks/sources or add custom obfuscation. It simply ingests currents lists, and, in some cases, changes known values of remote resources (domains/IPs) to a set value that can be used in a payload list.

Sources:
- https://github.com/PortSwigger/xss-cheatsheet-data
- http://htmlpurifier.org/live/smoketests/xssAttacks.xml 

```
usage: xsswig.py [-h]
                 [-g {protocols,dangling_markup,useful_tags,special_tags,restricted_characters,encodings,classic,obfuscation,polyglot,waf_bypass_global_obj,frameworks,angularjs,vuejs,purifier}]
                 [-m {all,simple,extended,events,automatic,interactive}] [-e EVENT_NAME] [-b {firefox,chrome,edge,safari,opera}]
                 [-l MIN_BROWSERS] [-r REMOTE_HOST] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -g {protocols,dangling_markup,useful_tags,special_tags,restricted_characters,encodings,classic,obfuscation,polyglot,waf_bypass_global_obj,frameworks,angularjs,vuejs,purifier}, --group {protocols,dangling_markup,useful_tags,special_tags,restricted_characters,encodings,classic,obfuscation,polyglot,waf_bypass_global_obj,frameworks,angularjs,vuejs,purifier}
                        Payload group name to include (i.e. -g classic -g angularjs
  -m {all,simple,extended,events,automatic,interactive}, --meta-group {all,simple,extended,events,automatic,interactive}
                        Groups of payload groups to include (i.e. -m simple -m automatic
  -e EVENT_NAME, --event-name EVENT_NAME
                        Filter for only specific events (i.e. -e onfocus -e onload)
  -b {firefox,chrome,edge,safari,opera}, --browser {firefox,chrome,edge,safari,opera}
                        Only return payloads that work on a browser. Only works for supported groups
  -l MIN_BROWSERS, --min-browsers MIN_BROWSERS
                        Only return payloads that match a certain number of browsers (Default is to match at least 2)
  -r REMOTE_HOST, --remote-host REMOTE_HOST
                        Set to change remote domains such ha.ckers.net to a specific domain or IP. (Default is 'LHOST')
  -v, --verbose         Print group names
```
