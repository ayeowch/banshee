#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Read web server access log file and ban abusive IP addresses.
"""

import datetime
import json
import os
import optparse
import re
import signal
import socket
import struct
import sys
import time
import urllib
import urllib2
from subprocess import Popen, PIPE

CONFIG = {
    # API to add newly banned IP address
    'ban_ip_url': 'http://localhost/ip/ban_ip',

    # API to return the country information for the given IP_ADDRESS
    'ip_country': 'http://dazzlepod.com/ip/IP_ADDRESS.json',

    # Magic key is required for all HTTP POST requests sent to the API above
    'magic_key': 'iLzmJkPe8JbzMmt30Frz',

    # User agent to use for all HTTP requests made by Banshee
    'user_agent': 'banshee/1.1 (+https://github.com/ayeowch/banshee)',

    # Generic delay
    'delay': 1,

    # Number of lines to tail from the access log
    'tail_lines': 60,

    # The duration to run this Banshee instance
    'lifetime': 3600,

    # Max. requests that can be made from the same IP address within the
    # lifetime of this Banshee instance
    'max_requests': 30,

    # List of strings that may appear in request URL; these are the monitored
    # requests
    'watchlist': [
        '/app1',
        '/app2',
    ],

    # Requests from these user agents are always allowed
    'passthrough_user_agents': [
        ('Mozilla/5.0 (compatible; bingbot/2.0; '
         '+http://www.bing.com/bingbot.htm)'),
    ],

    # Requests from these networks are always allowed
    # Format: [<STARTING_IP_ADDRESS>, <SUBNET_MASK>],
    # Use struct.unpack('!I', socket.inet_pton(socket.AF_INET, '<VALUE>'))[0]
    # to get these integers
    # CIDR table: http://tools.ietf.org/rfc/rfc1878.txt
    'trusted_networks': (
        # Google - These networks are not listed in nslookup command below
        [1123631104, 4294959104],  # 66.249.64.0, 255.255.224.0
        [3419414528, 4294959104],  # 203.208.32.0, 255.255.224.0

        # Google - Use nslookup -q=TXT _netblocks.google.com 8.8.8.8 to get
        # current list
        [3639549952, 4294959104],  # 216.239.32.0, 255.255.224.0
        [1089052672, 4294959104],  # 64.233.160.0, 255.255.224.0
        [1123635200, 4294963200],  # 66.249.80.0, 255.255.240.0
        [1208926208, 4294950912],  # 72.14.192.0, 255.255.192.0
        [3512041472, 4294934528],  # 209.85.128.0, 255.255.128.0
        [1113980928, 4294963200],  # 66.102.0.0, 255.255.240.0
        [1249705984, 4294901760],  # 74.125.0.0, 255.255.0.0
        [1074921472, 4294963200],  # 64.18.0.0, 255.255.240.0
        [3481178112, 4294963200],  # 207.126.144.0, 255.255.240.0
        [2915172352, 4294901760],  # 173.194.0.0, 255.255.0.0
    ),

    # *****************
    # *** IMPORTANT ***
    # *****************
    # Banshee requires the following LogFormat in httpd.conf
    # LogFormat "%{X-Forwarded-For}i %l %u %t %T \"%r\" %>s %b \"%{Referer}i\"
    #           \"%{User-Agent}i\"" combined
    # See http://httpd.apache.org/docs/current/mod/mod_log_config.html#formats

    # Regex to extract valid entries from access log
    'log_regex': ('(?P<ip_addresses>[.:0-9a-fA-F, ]+) \[(?P<timestamp>.*?)\] '
                  '(?P<timetaken>[.\d]+) "(GET|HEAD|POST|OPTIONS) '
                  '(?P<request_url>.*?) HTTP/1.\d" (?P<status_code>\d+) '
                  '(\-|\d+) "(?P<referer>.*?)" "(?P<user_agent>.*?)"'),

    # Spamhaus: http://www.spamhaus.org/faq/section/DNSBL%20Usage
    # SpamCop: http://www.spamcop.net/fom-serve/cache/351.html
    'dnsbl_return_codes': [
        # SBL (Spamhaus), SpamCop
        '127.0.0.2',

        # CSS (Spamhaus)
        '127.0.0.3',
    ],

    # Only 1 request is allowed for IP from one of the rogue countries
    'rogue_countries': [],

    # Only 1 request is allowed if it originates from one of these rogue
    # referers
    'rogue_referers': [],

    # PID file for a running Banshee instance
    'pid_file': 'banshee.pid',
}


class Banshee(object):

    def __init__(self):
        super(Banshee, self).__init__()

        # Process ID for this instance; to be written into semaphore file
        self.pid = os.getpid()

        # Banshee database to hold information on the current state of the
        # access log
        # key = IP address
        # value = number of requests from this IP address
        self.db = {}

        # List of IP addresses banned by this Banshee instance
        self.banned = []

        # Datetime object for last analyzed log entry
        self.last_dt = None

    def is_already_running(self):
        if os.path.exists(CONFIG['pid_file']):
            pid = int(open(CONFIG['pid_file']).read())
            try:
                os.kill(pid, 0)
                return True
            except OSError:
                print("[%s] Removing stale %s (%d)" %
                      (str(datetime.datetime.now()), CONFIG['pid_file'], pid))
                os.remove(CONFIG['pid_file'])
        return False

    def create_pid_file(self):
        open(CONFIG['pid_file'], 'w').write("%s" % self.pid)

    def remove_pid_file(self):
        os.remove(CONFIG['pid_file'])

    def run(self):
        print("[%s] Starting Banshee.." % (str(datetime.datetime.now())))
        self.create_pid_file()

        self.access_log = self.options.access_log

        if not os.path.exists(self.access_log):
            print("Cannot find '%s'" % self.access_log)
            sys.exit(1)

        elapsed_time = 0
        while elapsed_time < CONFIG['lifetime']:
            # Exit on SIGINT, e.g. CTRL+C, or end of life
            signal.signal(signal.SIGINT, signal_handler)
            time.sleep(CONFIG['delay'])
            elapsed_time += CONFIG['delay']
            self.read_log_lines()

        self.remove_pid_file()
        print("\nExiting after %d seconds.." % CONFIG['lifetime'])
        sys.exit(0)

    def read_log_lines(self):
        f = open(self.access_log, 'r')
        log_lines = self.tail(f, CONFIG['tail_lines'])
        f.close()

        log_regex = CONFIG['log_regex']
        search = re.compile(log_regex).search
        for line in log_lines:
            match = search(line)
            if match:
                context = {
                    'ip_addresses': (match.group('ip_addresses').
                                     replace(' ', '').split(',')),
                    'timestamp': match.group('timestamp'),
                    'timetaken': match.group('timetaken'),
                    'request_url': match.group('request_url'),
                    'status_code': match.group('status_code'),
                    'referer': match.group('referer'),
                    'user_agent': match.group('user_agent'),
                }
                result = self.analyze(context)
            else:
                # If we caught error here, we probably have to come back here
                # and update the log_regex
                print("ERROR: %s" % line)
                sys.exit(1)

    def ip_country(self, ip_address):
        country = None
        url = CONFIG['ip_country'].replace('IP_ADDRESS', ip_address)

        json_data = self.urlopen(url)

        if json_data:
            data = json.loads(json_data)
            if 'error' in data:
                print("\t%s" % data['error'])
            else:
                country = data['country']
        else:
            print("\tCannot get country for %s" % ip_address)

        return country

    def is_from_trusted_network(self, ip_address):
        try:
            addr = struct.unpack('!I', socket.inet_pton(socket.AF_INET,
                                 ip_address))[0]
        except socket.error as err:
            return False

        for network in CONFIG['trusted_networks']:
            if (addr & network[1] == network[0]):
                return True

        return False

    def is_in_dnsbl(self, db_host, ip_address):
        is_listed = False

        reverse_ip_address = ".".join(ip_address.split(".")[::-1])

        if not reverse_ip_address:
            return is_listed

        cmd = "dig +short in a %s.%s" % (reverse_ip_address, db_host)
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        returncode = p.returncode

        if returncode != 0:
            print("ERROR: %s" % stderr)
            sys.exit(returncode)

        stdout = stdout.strip()
        if stdout and stdout in CONFIG['dnsbl_return_codes']:
            is_listed = True

        return is_listed

    def analyze(self, context):
        if context['status_code'] == '403':
            return 0

        if context['user_agent'] in CONFIG['passthrough_user_agents']:
            return 0

        is_drop = True
        for item in CONFIG['watchlist']:
            if item in context['request_url']:
                is_drop = False
        if is_drop:
            return 0

        # Ignore timezone as we assume they are all the same; we can't easily
        # parse them anyway into datetime object
        # 11/Nov/2011:23:37:28 +0800
        timestamp = context['timestamp'].split(' ')[0]
        dt = datetime.datetime.fromtimestamp(
            time.mktime(time.strptime(timestamp, "%d/%b/%Y:%H:%M:%S")))

        # dt represents the time when the request was received but we want it
        # to represent the time when the request is completed/logged
        timetaken = float(context['timetaken'])
        if timetaken > 0:
            dt = dt + datetime.timedelta(seconds=(timetaken + 1))

        is_drop = True
        if self.last_dt:
            if dt > self.last_dt:
                self.last_dt = dt
                is_drop = False
        else:
            self.last_dt = dt
            is_drop = False
        if is_drop:
            return 0

        for ip_address in context['ip_addresses']:
            if ip_address in self.banned:
                continue

            if self.is_from_trusted_network(ip_address):
                print("[%s] %s originates from trusted network" %
                      (dt, ip_address))
                continue

            ban_reason = None

            if context['referer'] in CONFIG['rogue_referers']:
                ban_reason = "%s has rogue referer" % ip_address

            if ip_address in self.db:
                self.db[ip_address] += 1

                print("[%s] [%d] %s %s" %
                      (dt, self.db[ip_address], ip_address,
                       context['user_agent']))
                print("\t%s" % context['request_url'])

                if self.db[ip_address] >= CONFIG['max_requests']:
                    ban_reason = "%s exceeded max. requests" % ip_address
            else:
                self.db[ip_address] = 1

                if self.is_in_dnsbl('zen.spamhaus.org', ip_address):
                    ban_reason = "%s is listed in Spamhaus DNSBL" % ip_address

                elif self.is_in_dnsbl('bl.spamcop.net', ip_address):
                    ban_reason = "%s is listed in SpamCop DNSBL" % ip_address

                else:
                    country = self.ip_country(ip_address)
                    if country and country in CONFIG['rogue_countries']:
                        ban_reason = "%s originates from %s" % (ip_address,
                                                                country)

            if ban_reason:
                print("[%s] %s, banning.." % (dt, ban_reason))
                response = self.ban_ip(ip_address, ban_reason)
                if response:
                    print("\t%s" % response)
                    self.banned.append(ip_address)

    def tail(self, f, n):
        assert n >= 0
        pos, lines = n + 1, []
        while len(lines) <= n:
            try:
                f.seek(-pos, 2)
            except IOError:
                f.seek(0)
                break
            finally:
                lines = list(f)
            pos *= 2
        return lines[-n:]

    def ban_ip(self, ip_address, reason):
        url = "%s/%s/" % (CONFIG['ban_ip_url'], ip_address,)
        context = {
            'magic_key': CONFIG['magic_key'],
            'reason': reason,
        }
        response = self.urlopen(url, context)
        return response

    def urlopen(self, url, context=None):
        response = None

        request = urllib2.Request(url=url)
        request.add_header('User-Agent', CONFIG['user_agent'])
        if context:
            data = urllib.urlencode(context)
            request.add_data(data)

        try:
            response = urllib2.urlopen(request).read()
        except urllib2.HTTPError as err:
            print("\tHTTPError: %s (%s)" % (url, err.code))
        except urllib2.URLError as err:
            print("\tURLError: %s (%s)" % (url, err.reason))

        return response


def signal_handler(signal, frame):
    print("\nCaught SIGINT, exiting in %d seconds.." % CONFIG['delay'])
    time.sleep(CONFIG['delay'])
    sys.exit(0)


def main():
    usage = """%prog --access_log=ACCESS_LOG"""
    cmdparser = optparse.OptionParser(usage, version="banshee 1.1")
    cmdparser.add_option("-a", "--access_log", type="string", default="",
                         help="web server access log file")
    options, args = cmdparser.parse_args()

    if options.access_log:
        banshee = Banshee()
        banshee.options = options
        if not banshee.is_already_running():
            banshee.run()
    else:
        cmdparser.print_usage()

    return 0


if __name__ == '__main__':
    sys.exit(main())
