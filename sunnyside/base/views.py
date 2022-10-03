from base64 import urlsafe_b64encode
from ipaddress import ip_address
from multiprocessing import context
from re import template
from statistics import mode
from xml.parsers.expat import model
from django.shortcuts import render, redirect
from django.db.models import Q
from django.contrib.auth import authenticate, login, logout
from django import forms
from .models import ipModel, supercategory, category, subcategory, item
from analytics.models import UserSession, ObjectViewed
from .forms import UserCreationForm, PasswordResetForm, SignUpX, RecoverX
from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponse
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth import get_user_model
from django.core.validators import validate_email
from django.conf import settings
from django.conf.urls.static import static
from django.db import models
from django.http import JsonResponse
from django.core import serializers
from next_prev import next_in_order, prev_in_order
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import UpdateUserForm, UpdateProfileForm
from django.views.generic.list import ListView

from django.urls import reverse_lazy
from django.contrib.auth.views import PasswordChangeView
from django.contrib.messages.views import SuccessMessageMixin

from analytics.signals import object_viewed_signal
from base.signals import user_logged_in
from analytics.mixins import ObjectViewMixin

from django.contrib.auth.mixins import UserPassesTestMixin
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import user_passes_test
from django.db.models import Count


class ChangePasswordView(SuccessMessageMixin, PasswordChangeView):
    template_name = 'changepassword.html'
    success_message = "Successfully Changed Your Password"
    success_url = reverse_lazy('editprofile')


class user(models.Model):
    profilepic = models.ImageField(
        upload_to='profile', blank=True, default='preview/default.jpg')
# Credentials-Stuff


def loginfail(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('explore')
        else:
            return redirect('error')

    return render(request, 'base/loginfail.html')


def loginUser(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            user_logged_in.send(user.__class__, instance=user, request=request)
            return redirect('explore')
        else:
            return redirect('error')

    return render(request, 'base/login.html')


def logoutUser(request):
    logout(request)
    return redirect('explore')


def signupUser(request):
    form = SignUpX()
    if request.method == "POST":
        form = SignUpX(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password1")
            user = form.save(commit=False)
            user.save()
            user = authenticate(request, username=user.username,
                                password=request.POST['password1'])
            if user is not None:
                login(request, user)
                return redirect("explore")
            else:
                return redirect("signup")

    context = {'form': form}
    return render(request, 'base/signup.html', context)


def recover(request):
    recover_form = RecoverX()
    if request.method == "POST":
        recover_form = RecoverX(request.POST)
        if recover_form.is_valid():
            data = recover_form.cleaned_data.get('email')
        user_email = User.objects.filter(Q(email=data))
        if user_email.exists():
            for user in user_email:
                subject = 'Password Reset request'
                email_template_name = 'base/recovertemplate.txt'
                parameters = {
                    'email': user.email,
                    'domain': '127.0.0.1:5000',
                    'site_name': 'Billykiseu.com',
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                    'protocol': 'http',
                }
                email = render_to_string(email_template_name, parameters)
                try:
                    send_mail(subject, email, '', [
                              user.email], fail_silently=False)
                except:
                    return HttpResponse('Invalid Header')
                return redirect('recoverdone')
        else:
            return redirect('recoverfail')

    context = {
        'recover_form': recover_form,
    }
    return render(request, 'base/recover.html', context)


def recoverfail(request):
    recover_form = RecoverX()
    if request.method == "POST":
        recover_form = RecoverX(request.POST)
        if recover_form.is_valid():
            data = recover_form.cleaned_data.get('email')
        user_email = User.objects.filter(Q(email=data))
        if user_email.exists():
            for user in user_email:
                subject = 'Password Reset request'
                email_template_name = 'base/recovertemplate.txt'
                parameters = {
                    'email': user.email,
                    'domain': '127.0.0.1:5000',
                    'site_name': 'Billykiseu.com',
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                    'protocol': 'http',
                }
                email = render_to_string(email_template_name, parameters)
                try:
                    send_mail(subject, email, '', [
                              user.email], fail_silently=False)
                except:
                    return HttpResponse('Invalid Header')
                return redirect('recoverdone')
        else:
            #recover_form = RecoverX
            return redirect('recoverfail')

    context = {
        'recover_form': recover_form,
    }
    return render(request, 'base/recoverfail.html', context)

# Editprofile


@login_required(login_url='login')
def profile(request):
    if request.method == 'POST':
        user_form = UpdateUserForm(request.POST, instance=request.user)
        profile_form = UpdateProfileForm(
            request.POST, request.FILES, instance=request.user.profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your profile is updated successfully')
            return redirect('editprofile')
    else:
        user_form = UpdateUserForm(instance=request.user)
        profile_form = UpdateProfileForm(instance=request.user.profile)

    return render(request, 'editprofile.html', {'user_form': user_form, 'profile_form': profile_form})

# filters


def explore(request):
    allitems = item.objects.all()
    item_count = allitems.count()
    music = 'music'
    art = 'digital.art'
    code = 'code'
    musicitems2 = item.objects.filter(supercategory__name=music)
    artitems2 = item.objects.filter(supercategory__name=art)
    codeitems2 = item.objects.filter(supercategory__name=code)
    musicdrop = category.objects.filter(supercategory__name='music')
    artdrop = category.objects.filter(supercategory__name='digital.art')
    codedrop = category.objects.filter(supercategory__name='code')
    cue = item.objects.filter(supercategory__name=music)

    # FeatureItems
    featuredmusic = item.objects.filter(rank='10').filter(
        supercategory__name='music').order_by('-updated')
    featuredart = item.objects.filter(rank='10').filter(
        supercategory__name='digital.art').order_by('-updated')

    context = {'musicitems2': musicitems2, 'artitems2': artitems2, 'codeitems2': codeitems2, 'item_count': item_count,
               'musicdrop': musicdrop, 'artdrop': artdrop, 'codedrop': codedrop, 'featuredmusic': featuredmusic, 'featuredart': featuredart,
               'cue': cue}

    return render(request, 'base/explore.html', context)


def globalsearch(request):
    q = request.GET.get('q') if request.GET.get('q') != None else ''
    gsearch = item.objects.filter(
        Q(supercategory__name__icontains=q) |
        Q(category__name__icontains=q) |
        Q(subcategory__name__icontains=q) |
        Q(name__icontains=q) |
        Q(tags__icontains=q) |
        Q(description__icontains=q)
    ).order_by('-created')

    item_count = gsearch.count()

    context = {'gsearch': gsearch, 'item_count': item_count}
    return render(request, 'base/gsearch.html', context)


def autocomplete(request):
    address = request.GET.get('suggestions') if request.GET.get(
        'suggestions') != None else ''
    payload = []
    if address:
        suggestions = item.objects.filter(name__icontains=address)

        for suggestions in suggestions:
            payload.append(suggestions.name)
    return JsonResponse({'status': 200, 'data': payload})


def musicfilter(request):
    name = 'music'
    musicitems = item.objects.filter(supercategory__name=name)
    item_count = musicitems.count()
    context = {'musicitems': musicitems, 'item_count': item_count}
    return render(request, 'base/music.html', context)


def digitalartfilter(request):
    name = 'digital.art'
    artitems = item.objects.filter(supercategory__name=name)
    supercat = supercategory.objects.get(name=name)
    item_count = artitems.count()

    context = {'supercat': supercat,
               'artitems': artitems, 'item_count': item_count}
    return render(request, 'base/digitalart.html', context)


def codefilter(request):
    name = 'code'
    codeitems = item.objects.filter(supercategory__name=name)
    supercat = supercategory.objects.get(name=name)
    item_count = codeitems.count()

    context = {'supercat': supercat,
               'codeitems': codeitems, 'item_count': item_count}
    return render(request, 'base/code.html', context)


# furtherfiltering
def subfilter1(request, name):
    filter2 = item.objects.filter(
        supercategory__name=name).order_by('-updated')
    cat = supercategory.objects.get(name=name)
    item_count = filter2.count()
    context = {'cat': cat, 'filter2': filter2, 'item_count': item_count}
    return render(request, 'base/filter2.html', context)


def subfilter2(request, name, name2):
    filter3 = item.objects.filter(
        supercategory__name=name).order_by('-updated')
    filter4 = item.objects.filter(category__name=name2).order_by('-updated')
    cat = supercategory.objects.get(name=name)
    cat2 = category.objects.get(name=name2)
    item_count = filter4.count()
    context = {'filter3': filter3, 'filter4': filter4,
               'cat': cat, 'cat2': cat2, 'item_count': item_count}
    return render(request, 'base/filter3.html', context)


def subfilter3(request, name, name2, name3):
    filter5 = item.objects.filter(
        supercategory__name=name).order_by('-updated')
    filter6 = item.objects.filter(category__name=name2).order_by('-updated')
    filter7 = item.objects.filter(subcategory__name=name3).order_by('-updated')
    cat = supercategory.objects.get(name=name)
    cat2 = category.objects.get(name=name2)
    cat3 = subcategory.objects.get(name=name3)
    item_count = filter7.count()
    context = {'filter5': filter5, 'filter6': filter6, 'filter7': filter7,
               'cat': cat, 'cat2': cat2, 'cat3': cat3, 'item_count': item_count}
    return render(request, 'base/filter4.html', context)

# playmusic
# @login_required(login_url='login')


def cue(request, name):
    musicitems = item.objects.filter(
        supercategory__name='music').order_by('-updated')
    playing = item.objects.filter(
        supercategory__name='music').filter(name=name)
    item_count = musicitems.count()
    qs = item.objects.filter(supercategory__name='music')
    newest = qs.first()
    nextsong = next_in_order(newest, qs=qs)
    previoussong = prev_in_order(newest, qs=qs, loop=True)
    ip = request.META['REMOTE_ADDR']
    senderx = 'base'
    sendery = 'item'

    if ipModel.objects.filter(ip=ip).exists():
        print("ip alredy present")
        sunny = item.objects.get(name=name)
        print(sunny)
        ip = request.META['REMOTE_ADDR']
        print(ip)
        sunny.views.add(ipModel.objects.get(ip=ip))
        object_viewed_signal.send(
            sunny, label=senderx, model=sendery, instance=sunny, request=request)
    else:
        print("view counted")
        sunny = item.objects.get(name=name)
        print(sunny)
        ip = request.META['REMOTE_ADDR']
        print(ip)
        ipModel.objects.create(ip=ip)
        sunny.views.add(ipModel.objects.get(ip=ip))
        object_viewed_signal.send(
            sunny, label=senderx, model=sendery, instance=sunny, request=request)

    context = {'ip': ip, 'playing': playing, 'item_count': item_count, 'musicitems': musicitems,
               'newest': newest, 'qs': qs,
               'nextsong': nextsong, 'previoussong': previoussong
               }
    return render(request, 'base/play.html', context)


# analytics


@user_passes_test(lambda u: u.is_superuser)
def analytics(request):
    music = 'music'
    # only works on postgres
    #uniquesitevisitlist = ObjectViewed.objects.distinct('ip_address')
    uniquesitevisitlist = ObjectViewed.objects.distinct()
    uniquesitevisits = uniquesitevisitlist.count()
    registeredvisitlist = UserSession.objects.all()
    registeredvisits = registeredvisitlist.count()
    registereduserslist = User.objects.all()
    registeredusers = registereduserslist.count()
    musicstats = item.objects.filter(
        supercategory__name=music)
    musicplaylist = ObjectViewed.objects.all()
    totalplays = musicplaylist.count()
    #activeuserlist = UserSession.objects.filter(active=True).distinct('ip_address')
    activeuserlist = UserSession.objects.filter(
        active=True).distinct()
    activeusers = activeuserlist.count()

    context = {'uniquesitevisits': uniquesitevisits,  'registeredvisits': registeredvisits,
               'registeredusers': registeredusers, 'musicstats': musicstats, 'totalplays': totalplays, 'activeusers': activeusers}
    return render(request, 'base/analytics.html', context)
