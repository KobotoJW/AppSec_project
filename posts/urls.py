from django.urls import path
from . import views

app_name = 'posts'

urlpatterns = [
                 
    path('', views.feed, name='feed'),
    
                     
    path('create/', views.create_post, name='create_post'),
    path('<uuid:post_id>/', views.post_detail, name='post_detail'),
    path('<uuid:post_id>/delete/', views.delete_post, name='delete_post'),
    
                        
    path('<uuid:post_id>/comment/', views.add_comment, name='add_comment'),
    path('comment/<uuid:comment_id>/delete/', views.delete_comment, name='delete_comment'),
    
            
    path('<uuid:post_id>/rate/', views.rate_post, name='rate_post'),
    
                       
    path('report/<str:content_type>/<uuid:content_id>/', views.report_content, name='report_content'),
    
                      
    path('moderation/queue/', views.moderation_queue, name='moderation_queue'),
    path('moderation/report/<uuid:report_id>/handle/', views.handle_report, name='handle_report'),
    path('moderation/restore/<str:content_type>/<uuid:content_id>/', views.restore_content, name='restore_content'),
]
