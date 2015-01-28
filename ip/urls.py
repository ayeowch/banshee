from django.conf.urls import patterns
from ip.views import ban_ip


urlpatterns = patterns('',
    (r'^ban_ip/(?P<ip_address>[\w\.]+)/$', ban_ip),
)
