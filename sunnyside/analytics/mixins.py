# analytics.mixins.py

from multiprocessing import context
from .signals import object_viewed_signal

class ObjectViewMixin(object):
    def get_context_data(self, request, *args,**kwargs):
        context= super(ObjectViewMixin, self).get_context_data(*args, **kwargs)
        request =self.request
        instance= context.get('object')
        if instance:
          object_viewed_signal.send(instance.__class__, instance=instance, request=request)
        return context
        