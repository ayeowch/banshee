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

    if request.POST.has_key('magic_key') and request.POST['magic_key'].strip() == 'iLzmJkPe8JbzMmt30Frz':
        pass
    else:
        return HttpResponse('--')

    if ip_address and user_agent == 'banshee/1.1 (+https://github.com/ayeowch/banshee)':
        reason = ''
        if request.POST.has_key('reason'):
            reason = request.POST['reason'].strip()

        try:
            ip = BannedIp.objects.get(ip = ip_address)
        except BannedIp.DoesNotExist:
            ip = BannedIp(ip = ip_address, reason = reason)
            ip.save()
            return HttpResponse('+ %s' % ip_address)

    return HttpResponse('--')
