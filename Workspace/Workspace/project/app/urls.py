from django.urls import path 
from . import views 

urlpatterns= [ 
 path('index/',views.get_all_emails,name='index'),
 path('chart.html/',views.chart,name='chart'),
 path('widget.html/',views.get_and_analyze_emails,name='widget'),
 path('email/<str:email_id>/', views.email_detail, name='email_detail'),
 path('inbox/', views.get_and_analyze_emails, name='inbox'),
 path('', views.login, name='login'), 
 path('profile', views.profile, name='profile'), 
 path('login/', views.logout1, name='logout'),
 path('emails/<str:message_id>/delete/', views.delete_email_by_id, name='email_delete'),
 path('emails/scan/<str:message_id>/', views.email_scan, name='email_scan'),
 path('compose/', views.compose, name='compose'),



 
 



]