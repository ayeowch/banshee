# banshee
Banshee is a Python script that tails your access log and ban abusive IP addresses from accessing your Django applications.

## Installation

Place the 'ip' directory into your Django project directory.

Update your project settings.py by adding 'ip' into your INSTALLED_APPS.

Run 'python manage.py syncdb', you should see this:

    Creating table ip_bannedip

Update at least the following 3 entries in banshee.config:

    # API to add newly banned IP address
    'ban_ip_url': 'http://localhost/ip/ban_ip'

    # Magic key is required for all HTTP POST requests sent to the API above
    'magic_key': 'iLzmJkPe8JbzMmt30Frz',

    # List of strings that may appear in request URL; these are the monitored requests
    'watchlist':  [
        '/app1',
        '/app2',
    ],

Add a cronjob entry to ensure banshee.py is always running, example:

    * * * * * python BANSHEE_PY --access_log=ACCESS_LOG >> banshee.log 2>&1

* Replace BANSHEE_PY with the absolute path to banshee.py
* Replace ACCESS_LOG with the absolute path to your web server access log
* Piping the STDOUT and STDERR to banshee.log is optional

## Usage

Use `ip.is_allowed_ip` view function to check if an IP address has been banned.

The default max. requests that a particular IP address can make within 60 minutes period is set to 30.
Change `banshee.config['max_requests']` if you wish to increase or decrease this value.

Certain user agents are never banned by banshee.
You may want to change the list of these user agents in `banshee.config['passthrough_user_agents']`

Instead of whitelisting user agents, a better alternative would be to always allow requests from a trusted network.
You may update the list of networks that you trust in `banshee.config['trusted_networks']`

Banshee recognizes web server access log that uses the following log format:

    LogFormat "%{X-Forwarded-For}i %l %u %t %T \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
