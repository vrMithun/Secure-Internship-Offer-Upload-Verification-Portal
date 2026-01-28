from django.contrib import admin
from .models import User, Offer, OTP
# Register your models here.
admin.site.register(User)
admin.site.register(Offer)
admin.site.register(OTP)