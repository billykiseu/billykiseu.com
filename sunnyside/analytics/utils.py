# analytics.utils.py
from urllib import response
from ip2geotools.databases.noncommercial import DbIpCity


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get('REMOTE_ADDR', None)
    return ip


def get_client_loc(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        try:
            ip = request.META.get('REMOTE_ADDR', None)
            response = DbIpCity.get(ip, api_key='free')
            location = response.country + "|" + response.city
        except:
            location = "unknown"

    return location
