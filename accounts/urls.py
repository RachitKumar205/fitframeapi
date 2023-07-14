from django.urls import path

from .views import ChangePasswordView, LoginView, UpdateProfileView, UserRegistrationView

urlpatterns = [
    path("register/", UserRegistrationView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("update-profile/<int:pk>/", UpdateProfileView.as_view(), name="update-profile"),
    path(
        "change-password/<int:pk>/",
        ChangePasswordView.as_view(),
        name="change-password",
    ),
]