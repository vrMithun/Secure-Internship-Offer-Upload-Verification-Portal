from django.urls import path
from . import views

urlpatterns = [
    path("register/", views.register, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("verify-otp/", views.verify_otp, name="verify_otp"),
    path("upload-offer/", views.upload_offer, name="upload_offer"),
    path("offers/", views.list_offers, name="list_offers"),
    path("offers/verify/<int:offer_id>/", views.verify_offer, name="verify_offer"),
    path("offers/<int:offer_id>/", views.view_offer, name="view_offer"),
    path("offers/delete/<int:offer_id>/", views.delete_offer, name="delete_offer"),
    path("offers/approve-deletion/<int:request_id>/", views.approve_deletion, name="approve_deletion"),
    path("offers/approve-verification/<int:request_id>/", views.approve_verification, name="approve_verification"),
    path("offers/accept/<int:offer_id>/", views.accept_offer, name="accept_offer"),
    path("notifications/", views.notifications, name="notifications"),
    path("activity-log/", views.activity_log, name="activity_log"),

]
