from re import template
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
from . import views

# patterns
urlpatterns = [
    path('', views.explore, name="explore"),
    path('explore', views.explore, name="explore"),
    path('gsearch', views.globalsearch, name="gsearch"),
    path('music', views.musicfilter, name="music"),
    path('digitalart', views.digitalartfilter, name="digitalart"),
    path('code', views.codefilter, name="code"),
    path('login', views.loginUser, name="login"),
    path('logout', views.logoutUser, name="logout"),
    path('signup', views.signupUser, name="signup"),
    path('recover/', views.recover, name="recover"),
    path('recoverdone/', auth_views.PasswordResetDoneView.as_view(
        template_name="base/recoverdone.html"), name="recoverdone"),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name="base/reset.html"), name="password_reset_confirm"),
    path('recovercomplete/', auth_views.PasswordResetCompleteView.as_view(
        template_name="base/recovercomplete.html"), name="password_reset_complete"),
    path('loginfail/', views.loginfail, name="loginfail"),
    path('recoverfail/', views.recoverfail, name="recoverfail"),
    path('search/', views.autocomplete, name="search"),
    path('explore/<str:name>', views.subfilter1, name="supercategory"),
    path('explore/<str:name>/<str:name2>', views.subfilter2, name="category"),
    path('explore/<str:name>/<str:name2>/<str:name3>',
         views.subfilter3, name="subcategory"),
    path('play', views.cue, name="play"),
    path('play/<str:name>', views.cue, name="play"),
    path('change-password/', views.ChangePasswordView.as_view(),
         name='change-password'),
    path('editprofile/', views.profile, name="editprofile"),
    path('analytics/', views.analytics, name="analytics"),

    # Errors
    path('loginfail/login', views.loginfail, name="error"),

]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)
