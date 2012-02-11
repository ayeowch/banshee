from django.contrib import admin
from ip.models import *


class BannedIpAdmin(admin.ModelAdmin):
    list_display = ('date', 'ip',)
    list_filter = ['date',]
    search_fields = ['ip',]
    ordering = ('-date',)
admin.site.register(BannedIp, BannedIpAdmin)
