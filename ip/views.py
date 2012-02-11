from django.http import HttpResponse
from ip.models import *


def is_allowed_ip(ip):
    if not ip:
        return True
    try:
        blacklist = BannedIp.objects.get(ip = ip)
        return False
    except BannedIp.DoesNotExist:
        return True


def get_user_agent(request):
    user_agent = ''
    if request.META.has_key('HTTP_USER_AGENT'):
        user_agent = request.META['HTTP_USER_AGENT']
    return user_agent


def ban_ip(request, ip_address=None):
    user_agent = get_user_agent(request)
    if request.method == 'POST' and user_agent == 'banshee' and ip_address:
        try:
            ip = BannedIp.objects.get(ip = ip_address)
        except BannedIp.DoesNotExist:
            ip = BannedIp(ip = ip_address)
            ip.save()
            return HttpResponse('+ %s' % ip_address)
    return HttpResponse('--')
