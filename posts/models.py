import uuid
import os
from django.db import models
from django.conf import settings
from django.core.validators import FileExtensionValidator, MinValueValidator, MaxValueValidator
from django.utils import timezone


def get_upload_path(instance, filename):
    """Generate secure upload path with UUID to prevent path traversal"""
    ext = filename.split('.')[-1].lower()
    filename = f"{uuid.uuid4()}.{ext}"
    return os.path.join('posts', str(instance.author.id), filename)


class Post(models.Model):
    """Model for user posts with text and images"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='posts')
    content = models.TextField(max_length=5000, help_text="Post content")
    image = models.ImageField(
        upload_to=get_upload_path, 
        blank=True, 
        null=True,
        validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'gif', 'webp'])],
        help_text="Optional image attachment"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Moderation
    is_deleted = models.BooleanField(default=False, help_text="Soft delete flag")
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='deleted_posts'
    )
    
    # Reporting and moderation
    is_flagged = models.BooleanField(default=False, help_text="Flagged for moderation")
    flag_count = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['author', '-created_at']),
            models.Index(fields=['is_deleted', '-created_at']),
        ]
    
    def __str__(self):
        return f"Post by {self.author.email} at {self.created_at}"
    
    def get_rating_stats(self):
        """Get average rating and count"""
        ratings = self.ratings.all()
        if ratings.exists():
            avg = ratings.aggregate(models.Avg('value'))['value__avg']
            return {
                'average': round(avg, 1) if avg else 0,
                'count': ratings.count()
            }
        return {'average': 0, 'count': 0}
    
    def soft_delete(self, deleted_by_user):
        """Soft delete the post"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.deleted_by = deleted_by_user
        self.save()
    
    def restore(self):
        """Restore soft-deleted post"""
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.save()


class Comment(models.Model):
    """Model for comments on posts"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='comments')
    content = models.TextField(max_length=2000, help_text="Comment content")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Moderation
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='deleted_comments'
    )
    
    class Meta:
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['post', 'created_at']),
            models.Index(fields=['author', '-created_at']),
        ]
    
    def __str__(self):
        return f"Comment by {self.author.email} on {self.post.id}"
    
    def soft_delete(self, deleted_by_user):
        """Soft delete the comment"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.deleted_by = deleted_by_user
        self.save()
    
    def restore(self):
        """Restore soft-deleted comment"""
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.save()


class Rating(models.Model):
    """Model for post ratings (1-5 stars)"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='ratings')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='ratings')
    value = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        help_text="Rating value (1-5)"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['post', 'user']  # One rating per user per post
        indexes = [
            models.Index(fields=['post', 'user']),
        ]
    
    def __str__(self):
        return f"Rating {self.value} by {self.user.email} on {self.post.id}"


class ContentReport(models.Model):
    """Model for user reports on inappropriate content"""
    REPORT_REASONS = [
        ('spam', 'Spam'),
        ('inappropriate', 'Inappropriate Content'),
        ('harassment', 'Harassment'),
        ('violence', 'Violence'),
        ('copyright', 'Copyright Violation'),
        ('other', 'Other'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('reviewed', 'Reviewed'),
        ('action_taken', 'Action Taken'),
        ('dismissed', 'Dismissed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reporter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='reports_made')
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='reports', null=True, blank=True)
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE, related_name='reports', null=True, blank=True)
    
    reason = models.CharField(max_length=20, choices=REPORT_REASONS)
    description = models.TextField(max_length=1000, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Admin handling
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reports_reviewed'
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    admin_notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['reporter', '-created_at']),
        ]
    
    def __str__(self):
        content_type = 'Post' if self.post else 'Comment'
        return f"Report by {self.reporter.email} - {content_type} - {self.reason}"
