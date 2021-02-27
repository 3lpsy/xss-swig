#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path
import requests

VERBOSE = False

REMOTES = [
    "//evil",
    "subdomain1.portswigger-labs.net",
    "ssl.portswigger-labs.net",
    "portswigger-labs.net",
    "portswigger.net",
    "ha.ckers.org",
    "www.google.com",
    "google.com",
    "victimsite.com",
    "www.thesiteyouareon.com",
]

ENDPOINTS = [
    "validaudio.wav",
    "validaudio.mp3",
    "validvideo.mp4",
    "validimage.png",
    "validjs.js",
]

# good script would dynamically generate everything
# this is not one of those scripts
# let's filtering bad things that won't help
FILTER_CODE = [
    "66.102.7.147",
    "%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D",
    "1113982867",
    "0x42.0x0000066.0x7.0x93",
    "0102.0146.0007.00000223",
    "6.000146.0x7.147",
    "See Below",
]
# events are note simple
SIMPLE_GROUPS = [
    "protocols",
    "dangling_markup",
    "useful_tags",
    "special_tags",
    "restricted_characters",
    "encodings",
    "classic",
]

EXTENDED_SIMPLE_GROUPS = [
    "obfuscation",
    "polyglot",
    "waf_bypass_global_obj",
    "frameworks",
    "angularjs",
    "vuejs",
]

CUSTOM_GROUPS = ["purifier"]
GROUP_CHOICES = SIMPLE_GROUPS + EXTENDED_SIMPLE_GROUPS + CUSTOM_GROUPS
META_CHOICES = ["all", "simple", "extended", "events", "automatic", "interactive"]
BROWSER_CHOICES = ["firefox", "chrome", "edge", "safari", "opera"]
DATA_BASE_URL = (
    "https://raw.githubusercontent.com/PortSwigger/xss-cheatsheet-data/master/json"
)


def eprint(*args, **kwargs):
    global VERBOSE
    if VERBOSE:
        print(*args, file=sys.stderr, **kwargs)
    # print(*args, **kwargs)


def load(name, browsers=None, min_browsers=2):
    browsers = browsers or []
    if Path(f"loaded/{name}.json").is_file():
        with open(f"loaded/{name}.json", "r") as f:
            raw = json.load(f)
    elif Path(f"custom/{name}.json").is_file():
        with open(f"custom/{name}.json", "r") as f:
            raw = json.load(f)
    else:
        url = f"{DATA_BASE_URL}/{name}.json"
        eprint("[*] Attempting to load: {url}")
        res = requests.get(url)
        if res.status_code == 200:
            eprint(f"[*] Caching data to loaded/{name}.json")
            raw = json.loads(res.text)
            Path(f"loaded/{name}.json").write_text(res.text)
        else:
            raise Exception("Failed to find local custom file or load over network")

    if not isinstance(raw, list):
        conv = []
        # should probably just customize per wordlist so data
        # makes sense, but is fine for now
        for key, val in raw.items():
            if "key" in val.keys():
                raise Exception("Refactor required. Key index exists")
            val["key"] = key
            conv.append(val)
        raw = conv

    data = []

    for item in raw:
        if "browsers" in item:
            # filter out edge cases
            if browsers:
                for browser in item["browsers"]:
                    if browser in browsers:
                        data.append(item)
                        break
            elif len(item["browsers"]) >= min_browsers:
                data.append(item)
        else:
            data.append(item)
    return data


def out(code, lhost="LHOST"):
    # remove new line
    code = code.replace("\n", "")
    for f in FILTER_CODE:
        if f in code:
            return
    for r in REMOTES:
        code = code.replace(r, lhost)
    for e in ENDPOINTS:
        code = code.replace(e, lhost + "/x")
    print(code)


def simple(data, lhost="LHOST", code_key="code"):
    for item in data:
        code = item[code_key]
        out(item[code_key], lhost=lhost)


def group(groups, lhost="LHOST", browsers=None, min_browsers=2):
    code_key = "code"
    for grp in groups:
        title = grp.upper()
        data = load(grp, browsers=browsers, min_browsers=min_browsers)
        num = str(len(data))
        eprint(f"[*] Payload Group: {title} ({num})")
        if grp == "angularjs":
            code_key = "vector"
        simple(data, lhost=lhost, code_key=code_key)


def events_group(sub_groups, lhost="LHOST", events=None, browsers=None, min_browsers=2):
    filter_events = events or []
    # will place event name as "key" on item as of now
    events = load("events", browsers=browsers, min_browsers=min_browsers)
    data = []
    for e in events:
        tags = e["tags"]
        if filter_events and e["key"].lower() not in filter_events:
            continue
        for t in tags:
            if t["interaction"] and "interactive" in sub_groups:
                data.append(t)
            elif not t["interaction"] and "automatic" in sub_groups:
                data.append(t)
    num = len(data)
    title = f"events_{group}".upper()
    eprint(f"[*] Payload Group: {title} ({num})")
    simple(data, lhost=lhost)


def run(groups, meta, lhost, browsers, min_browsers, events):
    if "simple" in meta or "all" in meta:
        group(SIMPLE_GROUPS, lhost=lhost, browsers=browsers, min_browsers=min_browsers)

    if "events" in meta or "all" in meta:
        events_group(
            ["automatic", "interactive"],
            lhost=lhost,
            events=events,
            browsers=browsers,
            min_browsers=min_browsers,
        )
    elif "interactive" in meta:
        events_group(
            ["interactive"],
            lhost=lhost,
            events=events,
            browsers=browsers,
            min_browsers=min_browsers,
        )
    elif "automatic" in meta:
        events_group(
            ["automatic"],
            lhost=lhost,
            events=events,
            browsers=browsers,
            min_browsers=min_browsers,
        )

    if "extended" in meta or "all" in meta:
        group(
            EXTENDED_SIMPLE_GROUPS,
            lhost=lhost,
            browsers=browsers,
            min_browsers=min_browsers,
        )
    if groups:
        group(groups, lhost=lhost, browsers=browsers, min_browsers=min_browsers)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-g",
        "--group",
        choices=GROUP_CHOICES,
        action="append",
        help="Payload group name to include (i.e. -g classic -g angularjs",
    )
    parser.add_argument(
        "-m",
        "--meta-group",
        choices=META_CHOICES,
        action="append",
        help="Groups of payload groups to include (i.e. -m simple -m automatic",
    )
    parser.add_argument(
        "-e",
        "--event-name",
        action="append",
        help="Filter for only specific events (i.e. -e onfocus -e onload)",
    )
    parser.add_argument(
        "-b",
        "--browser",
        choices=BROWSER_CHOICES,
        action="append",
        help="Only return payloads that work on a browser. Only works for supported groups",
    )
    parser.add_argument(
        "-l",
        "--min-browsers",
        type=int,
        default=2,
        help="Only return payloads that match a certain number of browsers (Default is to match at least 2)",
    )
    parser.add_argument(
        "-r",
        "--remote-host",
        type=str,
        default="LHOST",
        help="Set to change remote domains such ha.ckers.net to a specific domain or IP. (Default is 'LHOST')",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Print group names"
    )
    args = parser.parse_args()
    groups = args.group or []
    metas = args.meta_group or []
    browsers = args.browser or []
    events = args.event_name or []
    if events:
        if "interactive" not in metas and "automatic" not in metas:
            metas.append("events")
        events = [e.lower() for e in events]
    if args.verbose:
        VERBOSE = True
    if not metas and not groups:
        metas = ["simple"]
    run(groups, metas, args.remote_host, browsers, args.min_browsers, events)
