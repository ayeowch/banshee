from django.db import models


class BannedIp(models.Model):
    ip =  models.IPAddressField(blank=True)
    date = models.DateTimeField(auto_now_add=True)

    def __unicode__(self):
        return "%s" % self.ip

    class Meta:
        verbose_name_plural = "Banned IP addresses"
