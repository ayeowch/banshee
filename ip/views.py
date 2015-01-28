from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from ip.models import BannedIp


def is_allowed_ip(ip):
    if not ip:
        return True
    if BannedIp.objects.filter(ip=ip).exists():
        return False
    return True


@csrf_exempt
def ban_ip(request, ip_address=None):
    if ip_address is None:
        return HttpResponse('--')
    magic_key = 'iLzmJkPe8JbzMmt30Frz'
    if 'magic_key' in request.POST and request.POST['magic_key'] == magic_key:
        pass
    else:
        return HttpResponse('--')
    reason = ''
    if 'reason' in request.POST:
        reason = request.POST['reason']
    try:
        ip = BannedIp.objects.get(ip=ip_address)
    except BannedIp.DoesNotExist:
        ip = BannedIp(ip=ip_address, reason=reason)
        ip.save()
        return HttpResponse('+ %s' % ip_address)
    return HttpResponse('--')
