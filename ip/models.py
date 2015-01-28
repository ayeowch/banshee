from django.db import models


class BannedIp(models.Model):
    ip = models.GenericIPAddressField(unique=True)
    date = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=255, blank=True)

    def __unicode__(self):
        return "%s" % self.ip

    class Meta:
        verbose_name_plural = "Banned IP addresses"
