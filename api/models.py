from django.db import models


class UserDetails(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    zip_code = models.CharField(max_length=100)
    floor_number = models.CharField(max_length=100)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "User Details"
        ordering = ['name']
