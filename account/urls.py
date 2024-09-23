from django.contrib import admin
from django.urls import path, include
from .views import ExampleView


urlpatterns = [
    path('protected_endpoint', ExampleView.as_view(), name="protected-endpoint"),
]