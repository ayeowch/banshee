from django.contrib import admin
from ip.models import BannedIp


class BannedIpAdmin(admin.ModelAdmin):
    list_display = ('date', 'ip', 'reason',)
    list_filter = ['date',]
    search_fields = ['ip', 'reason',]
    ordering = ('-date',)
admin.site.register(BannedIp, BannedIpAdmin)
