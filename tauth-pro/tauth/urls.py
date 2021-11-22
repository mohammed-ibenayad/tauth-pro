from django.urls import path

from . import views

urlpatterns = [
    path('api/user/refresh-token/', views.UserRefreshTokenView.as_view(), name='tauth-user-refresh-token'),
    path('api/user/logout/', views.UserLogoutView.as_view(), name='tauth-user-logout'),
    path('api/user/login/', views.UserLoginView.as_view(), name='tauth-user-login'),
]
