from django.contrib import admin
from .models import Post, Comment, Rating, ContentReport


@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'created_at', 'is_deleted', 'is_flagged', 'flag_count')
    list_filter = ('is_deleted', 'is_flagged', 'created_at')
    search_fields = ('author__email', 'content')
    readonly_fields = ('id', 'created_at', 'updated_at', 'deleted_at', 'deleted_by')
    
    fieldsets = (
        ('Content', {
            'fields': ('author', 'content', 'image')
        }),
        ('Moderation', {
            'fields': ('is_deleted', 'deleted_at', 'deleted_by', 'is_flagged', 'flag_count')
        }),
        ('Metadata', {
            'fields': ('id', 'created_at', 'updated_at')
        }),
    )


@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'post', 'created_at', 'is_deleted')
    list_filter = ('is_deleted', 'created_at')
    search_fields = ('author__email', 'content', 'post__content')
    readonly_fields = ('id', 'created_at', 'updated_at', 'deleted_at', 'deleted_by')


@admin.register(Rating)
class RatingAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'post', 'value', 'created_at')
    list_filter = ('value', 'created_at')
    search_fields = ('user__email', 'post__content')
    readonly_fields = ('id', 'created_at', 'updated_at')


@admin.register(ContentReport)
class ContentReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'reporter', 'reason', 'status', 'created_at', 'reviewed_by')
    list_filter = ('status', 'reason', 'created_at')
    search_fields = ('reporter__email', 'description')
    readonly_fields = ('id', 'created_at', 'reviewed_at')
    
    fieldsets = (
        ('Report Details', {
            'fields': ('reporter', 'post', 'comment', 'reason', 'description')
        }),
        ('Status', {
            'fields': ('status', 'reviewed_by', 'reviewed_at', 'admin_notes')
        }),
        ('Metadata', {
            'fields': ('id', 'created_at')
        }),
    )
