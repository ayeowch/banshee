from django.conf.urls.defaults import *
from ip.views import *


urlpatterns = patterns('',
    (r'^ban_ip/(?P<ip_address>[\w\.]+)/$', ban_ip),
)
