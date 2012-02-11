#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
banshee - Read web server access log file and ban abusive IP addresses.
"""

__author__ = 'Dazzlepod (info@dazzlepod.com)'
__copyright__ = 'Copyright (c) 2012 Dazzlepod'
__version__ = '0.1'

import datetime
import hashlib
import json
import os
import optparse
import re
import signal
import sys
import time
import urllib
import urllib2

config = {
    # API to add newly banned IP address
    'ban_ip_url': 'http://localhost/ip/ban_ip',

    # Generic delay
    'delay': 1,

    # Number of lines to tail from the access log
    'tail_lines': 5,

    # The duration to run this Banshee instance
    # If you set Banshee to run via cronjob, the interval should be equal to this setting to ensure continuous protection from Banshee
    'lifetime': 900,

    # Max. requests that can be made from the same IP address within the lifetime of this Banshee instance
    'max_requests': 50,

    # List of strings that may appear in request URL; these are the monitored requests
    'watchlist':  [
        '/app1',
        '/app2',
    ],

    # Requests from these user agents are always allowed
    'passthrough_user_agents': [
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
        'Mediapartners-Google',
    ],
    
    'log_regex': '(?P<remote_ip>[.:0-9a-fA-F]+) - - \[(?P<timestamp>.*?)\] "(GET|HEAD|POST) (?P<request_url>.*?) HTTP/1.\d" (?P<status_code>\d+) (\-|\d+) "(?P<referer>.*?)" "(?P<user_agent>.*?)"',
}


class Banshee(object):
    """Manage instance of Banshee."""

    def __init__(self):
        super(Banshee, self).__init__()

        # Banshee database to hold information on the current state of the access log
        # key = IP address
        # value = number of requests from this IP address
        self.db = {}

        # Datetime object for last analyzed log entry
        self.last_dt = None

    def run(self):
        print "[%s] Starting Banshee %s.." % (str(datetime.datetime.now()), __version__,)

        self.access_log = self.options.access_log

        if not os.path.exists(self.access_log):
            print "Cannot find '%s'" % self.access_log
            sys.exit(1)

        elapsed_time = 0
        while elapsed_time < config['lifetime']:
            # Exit on SIGINT, e.g. CTRL+C, or end of life
            signal.signal(signal.SIGINT, signal_handler)
            time.sleep(config['delay'])
            elapsed_time += config['delay']
            self.read_log_lines()

        print "\nExiting after %d seconds.." % config['lifetime']
        sys.exit(0)

    def read_log_lines(self):
        f = open(self.access_log, 'r')
        log_lines = self.tail(f, config['tail_lines'])
        f.close()

        log_regex = config['log_regex']
        search = re.compile(log_regex).search
        for line in log_lines:
            match = search(line)
            if match:
                context = {
                    'remote_ip': match.group('remote_ip'),
                    'timestamp': match.group('timestamp'),
                    'request_url': match.group('request_url'),
                    'status_code': match.group('status_code'),
                    'referer': match.group('referer'),
                    'user_agent': match.group('user_agent'),
                }
                result = self.analyze(context)
            else:
                # If we caught error here, we probably have to come back here and update the log_regex
                print "Error: %s" % line
                sys.exit(1)

    def analyze(self, context):
        if context['status_code'] != '200':
            return 0

        if context['user_agent'] in config['passthrough_user_agents']:
            return 0

        is_drop = True
        for item in config['watchlist']:
            if item in context['request_url']:
                is_drop = False
        if is_drop:
            return 0

        # Ignore timezone as we assume they are all the same; we can't easily parse them anyway into datetime object
        # 11/Nov/2011:23:37:28 +0800
        timestamp = context['timestamp'].split(' ')[0]
        dt = datetime.datetime.fromtimestamp(time.mktime(time.strptime(timestamp, "%d/%b/%Y:%H:%M:%S")))
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

        remote_ip = context['remote_ip']
        if self.db.has_key(context['remote_ip']):
            self.db[remote_ip] += 1
        else:
            self.db[remote_ip] = 1

        print "[%s] [%d]%s (%s)" % (dt, self.db[remote_ip], remote_ip, context['user_agent'],)
        print "\t%s" % context['request_url']

        if self.db[remote_ip] >= config['max_requests']:
            print "\t%s exceeded max. requests, banning.." % remote_ip
            self.ban_ip(remote_ip)

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

    def ban_ip(self, ip_address):
        url = "%s/%s/" % (config['ban_ip_url'], ip_address,)
        headers = {'User-Agent': 'banshee'}
        context = {}
        data = urllib.urlencode(context)
        request = urllib2.Request(url = url, headers = headers, data = data)
        try:
            page = urllib2.urlopen(request).read()
            print page
        except urllib2.URLError, e:
            print e.read()


def signal_handler(signal, frame):
    print "\nCaught SIGINT, exiting in %d seconds.." % config['delay']
    time.sleep(config['delay'])
    sys.exit(0)


def main():
    usage = """%prog --access_log=ACCESS_LOG"""
    cmdparser = optparse.OptionParser(usage, version=("banshee " + __version__))
    cmdparser.add_option("-a", "--access_log", type="string", default="", help="web server access log file")
    (options, args) = cmdparser.parse_args()

    if options.access_log:
        banshee = Banshee()
        banshee.options = options
        banshee.run()
    else:
        cmdparser.print_usage()

    return 0


if __name__ == '__main__':
    sys.exit(main())
