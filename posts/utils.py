from functools import wraps
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.utils import timezone
from datetime import timedelta
import hashlib


def rate_limit(key_prefix, max_requests, time_window_minutes):
    """
    Rate limiting decorator
    
    Args:
        key_prefix: Prefix for cache key (e.g., 'post_create', 'comment_add')
        max_requests: Maximum number of requests allowed
        time_window_minutes: Time window in minutes
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if request.user.is_authenticated:
                # Use user ID for authenticated users
                identifier = str(request.user.id)
            else:
                # Use IP address for anonymous users
                identifier = get_client_ip(request)
            
            cache_key = f"rate_limit:{key_prefix}:{identifier}"
            
            # Get current request count
            request_count = cache.get(cache_key, 0)
            
            if request_count >= max_requests:
                return HttpResponseForbidden(
                    f"Rate limit exceeded. Please try again in {time_window_minutes} minutes."
                )
            
            # Increment counter
            if request_count == 0:
                # First request - set expiry
                cache.set(cache_key, 1, time_window_minutes * 60)
            else:
                cache.incr(cache_key)
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def log_security_event(event_type, user=None, ip_address=None, user_agent=None, details=None, request=None):
    """Log security events for audit trail"""
    from accounts.models import SecurityEvent
    
    # Extract user_agent from request if not provided
    if user_agent is None and request is not None:
        user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
    
    # Default to 'Unknown' if still None
    if user_agent is None:
        user_agent = 'Unknown'
    
    event = SecurityEvent.objects.create(
        event_type=event_type,
        user=user,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details or {}
    )
    return event


def sanitize_filename(filename):
    """Sanitize uploaded filename to prevent path traversal"""
    import os
    import re
    
    # Get only the filename, not the path
    filename = os.path.basename(filename)
    
    # Remove any non-alphanumeric characters except dots and underscores
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    
    # Limit length
    name, ext = os.path.splitext(filename)
    if len(name) > 50:
        name = name[:50]
    
    return f"{name}{ext}"


def strip_image_metadata(image_file):
    """
    Strip EXIF and other metadata from uploaded images
    Returns a new image file with metadata removed
    """
    from PIL import Image
    import io
    
    # Open the image
    img = Image.open(image_file)
    
    # Create a new image without metadata
    data = list(img.getdata())
    image_without_exif = Image.new(img.mode, img.size)
    image_without_exif.putdata(data)
    
    # Save to bytes buffer
    output = io.BytesIO()
    
    # Determine format
    format = img.format if img.format else 'JPEG'
    if format == 'JPEG':
        image_without_exif.save(output, format='JPEG', quality=85, optimize=True)
    elif format == 'PNG':
        image_without_exif.save(output, format='PNG', optimize=True)
    else:
        image_without_exif.save(output, format=format)
    
    output.seek(0)
    return output


def reencode_image(image_file, max_size=(2048, 2048)):
    """
    Re-encode uploaded image to strip potential malicious code
    and resize if necessary
    """
    from PIL import Image
    import io
    
    img = Image.open(image_file)
    
    # Convert RGBA to RGB if necessary (for JPEG)
    if img.mode in ('RGBA', 'LA', 'P'):
        background = Image.new('RGB', img.size, (255, 255, 255))
        if img.mode == 'P':
            img = img.convert('RGBA')
        background.paste(img, mask=img.split()[-1] if img.mode in ('RGBA', 'LA') else None)
        img = background
    
    # Resize if necessary
    img.thumbnail(max_size, Image.Resampling.LANCZOS)
    
    # Save to bytes buffer
    output = io.BytesIO()
    img.save(output, format='JPEG', quality=85, optimize=True)
    output.seek(0)
    
    return output


def check_content_safety(text):
    """
    Basic content safety check
    Can be extended with ML-based moderation services
    """
    # List of blocked words/patterns
    blocked_patterns = [
        r'<script',
        r'javascript:',
        r'onerror=',
        r'onclick=',
    ]
    
    import re
    text_lower = text.lower()
    
    for pattern in blocked_patterns:
        if re.search(pattern, text_lower):
            return False, f"Content contains prohibited pattern: {pattern}"
    
    return True, "Content is safe"


def require_role(role):
    """
    Decorator to require specific user role
    
    Args:
        role: Required role ('user', 'admin')
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                from django.shortcuts import redirect
                return redirect('accounts:login')
            
            if role == 'admin' and not request.user.is_admin:
                return HttpResponseForbidden("Admin access required")
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
