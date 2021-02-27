#!/bin/sh
curl http://htmlpurifier.org/live/smoketests/xssAttacks.xml -o custom/purifier.xml;
python3 -c "from pathlib import Path;import xmltodict;import json;print(json.dumps(xmltodict.parse(Path('custom/purifier.xml').read_text())))" | jq -M '.xss.attack'| tee custom/purifier.json
