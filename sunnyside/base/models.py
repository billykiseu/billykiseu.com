from email.policy import default
import os.path
from cProfile import Profile
from email.mime import audio
from pyexpat import model
from socketserver import ThreadingUDPServer
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from django.contrib.contenttypes.fields import GenericRelation
from PIL import Image

#Databases
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profilepic = models.ImageField(upload_to='profile', blank=True, default='profile/test.jpg')

    def save(self, *args, **kwargs):
        super().save()
        img = Image.open(self.profilepic.path)
        if img.height > 100 or img.width > 100:
             new_img = (300, 300)
             img.thumbnail(new_img)
             img.save(self.profilepic.path)   

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()

class supercategory(models.Model):
    name = models.CharField(max_length=200)
    def __str__(self):
        return self.name

class category(models.Model):
    supercategory = models.ForeignKey(supercategory, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    def __str__(self):
        return self.name

class subcategory(models.Model):
    category = models.ForeignKey(category, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    previewimage = models.ImageField(upload_to='previews', blank=True, default='preview/default.jpg') 
    def __str__(self):
        return self.name

class ipModel(models.Model):
    ip=models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return self.ip

class item(models.Model):
    previewimage = models.ImageField(upload_to='previews', blank=True)  
    targetfile = models.FileField(upload_to='media', blank=True)
    #wavfile = models.FileField(upload_to='wav', blank=True)
    filetype = models.CharField(max_length=201,blank=True, choices=[('audio','audio'),('image','image'),('video','video'),('other','other')])
    name = models.CharField(max_length=200)
    artist = models.CharField(max_length=200,blank=True,default='Kiseu')
    duration = models.CharField(max_length=200,blank=True,default='00:00')
    supercategory = models.ForeignKey(supercategory, on_delete=models.CASCADE, null=True, blank=True)
    category = models.ForeignKey(category, on_delete=models.CASCADE, null=True, blank=True)
    subcategory = models.ForeignKey(subcategory, on_delete=models.CASCADE)
    tags = models.TextField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now=True)
    date = models.DateField(max_length=200,blank=True,default='0')
    rank = models.CharField(max_length=20,blank=True)
    mainlink = models.URLField(max_length=200,blank=True,default='#')
    youtubelink = models.URLField(max_length=200,blank=True,default='#')
    spotifylink = models.URLField(max_length=200,blank=True,default='#')
    applelink = models.URLField(max_length=200,blank=True,default='#')

    views = models.ManyToManyField(ipModel, related_name="post_views", blank=True)

    def __str__(self):
        return self.name

    def total_views(self):
        return self.views.count()

     #keeping things clean
    def save(self, *args, **kwargs):
        try:
            this = Image.objects.get(id=self.id)
            if this.image != self.image:
                this.image.delete(save=False)
        except:
            pass  # when new photo then we do nothing, normal case
        super().save(*args, **kwargs)


    



