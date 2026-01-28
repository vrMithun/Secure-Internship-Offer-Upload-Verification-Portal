from django.urls import path
from . import views

urlpatterns = [
    path("register/", views.register, name="register"),
    path("login/", views.login_view, name="login"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("verify-otp/", views.verify_otp, name="verify_otp"),
    path("upload-offer/", views.upload_offer, name="upload_offer"),
    path("offers/", views.list_offers, name="list_offers"),
    path("offers/verify/<int:offer_id>/", views.verify_offer, name="verify_offer"),
    path("offers/<int:offer_id>/", views.view_offer, name="view_offer"),

]
