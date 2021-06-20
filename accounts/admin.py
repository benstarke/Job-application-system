from django.contrib import admin
from .models import *


admin.site.site_header ="Online Job Recrutment System"

admin.site.register(User)

# admin.site.unregister(Groups)