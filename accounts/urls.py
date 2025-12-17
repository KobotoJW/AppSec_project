from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name='register'),
    path('register/success/', views.RegistrationSuccessView.as_view(), name='registration_success'),
    path('activation-success/', views.ActivationSuccessView.as_view(), name='activation_success'),
    path('activate/<str:token>/', views.ActivateAccountView.as_view(), name='activate'),
    path('resend-activation/', views.ResendActivationView.as_view(), name='resend_activation'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('password-reset/', views.PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password-reset/<str:token>/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
]
