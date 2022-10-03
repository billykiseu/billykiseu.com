from django.contrib import admin
from.models import Profile, ipModel, supercategory, category, subcategory, item

#Register your models here.
admin.site.register(Profile)
admin.site.register(supercategory)
admin.site.register(category)
admin.site.register(subcategory)
admin.site.register(item)
admin.site.register(ipModel)

