from functools import wraps
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.utils import timezone
from django.shortcuts import redirect
from datetime import timedelta
import ipaddress
import io
import re
from PIL import Image


def rate_limit(key_prefix, max_requests, time_window_minutes):
    """
    Rate limiting decorator with atomic operations
    
    Args:
        key_prefix: Prefix for cache key (e.g., 'post_create', 'comment_add')
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if request.user.is_authenticated:
                                                     
                identifier = str(request.user.id)
            else:
                                                    
                identifier = get_client_ip(request)
            
            cache_key = f"rate_limit:{key_prefix}:{identifier}"
            timeout = time_window_minutes * 60
            
                                        
            try:
                                                       
                current_count = cache.incr(cache_key)
                
                                                                
                if current_count == 1:
                    cache.touch(cache_key, timeout)
                    
            except ValueError:
                                                             
                cache.add(cache_key, 1, timeout)
                current_count = 1
            
                                     
            if current_count > max_requests:
                return HttpResponseForbidden(
                    f"Rate limit exceeded. Please try again in {time_window_minutes} minutes."
                )
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    
    if x_forwarded_for:
        ips = [ip.strip() for ip in x_forwarded_for.split(',')]
        
        for ip in reversed(ips):
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
                    return ip
            except ValueError:
                continue
    
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def log_security_event(event_type, user=None, ip_address=None, user_agent=None, details=None, request=None):
    from accounts.models import SecurityEvent
    
    if user_agent is None and request is not None:
        user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
    
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


def strip_image_metadata(image_file):
    img = Image.open(image_file)
    
    data = list(img.getdata())
    image_without_exif = Image.new(img.mode, img.size)
    image_without_exif.putdata(data)
    
    output = io.BytesIO()
    
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
    img = Image.open(image_file)
    
    if img.mode in ('RGBA', 'LA', 'P'):
        background = Image.new('RGB', img.size, (255, 255, 255))
        if img.mode == 'P':
            img = img.convert('RGBA')
        background.paste(img, mask=img.split()[-1] if img.mode in ('RGBA', 'LA') else None)
        img = background
    
    img.thumbnail(max_size, Image.Resampling.LANCZOS)
    
    output = io.BytesIO()
    img.save(output, format='JPEG', quality=85, optimize=True)
    output.seek(0)
    
    return output


def check_content_safety(text):
    text_normalized = text.lower()
    text_normalized = re.sub(r'\s+', ' ', text_normalized)
    
    blocked_patterns = [
        r'<\s*script',
        r'&lt;\s*script',
        r'javascript\s*:',
        r'jav\s*ascript\s*:',
        r'java\s*script\s*:',
        r'\bon\w+\s*=',
        r'onerror\s*=',
        r'onload\s*=',
        r'onclick\s*=',
        r'onmouseover\s*=',
        r'onmouseout\s*=',
        r'onfocus\s*=',
        r'onblur\s*=',
        r'onsubmit\s*=',
        r'onchange\s*=',
        r'<\s*iframe',
        r'<\s*object',
        r'<\s*embed',
        r'<\s*applet',
        r'<\s*meta',
        r'<\s*link',
        r'<\s*style',
        r'eval\s*\(',
        r'settimeout\s*\(',
        r'setinterval\s*\(',
        r'expression\s*\(',
        r'-moz-binding',
        r'vbscript\s*:',
        r'data\s*:\s*text/html',
        r'data\s*:\s*text/javascript',
        r'base64.*<\s*script',
        r'@import',
    ]
    
    for pattern in blocked_patterns:
        if re.search(pattern, text_normalized, re.IGNORECASE):
            return False, "Content contains potentially dangerous patterns"
    
    return True, "Content is safe"


def require_role(role):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('accounts:login')
            
            if role == 'admin' and not request.user.is_admin:
                return HttpResponseForbidden("Admin access required")
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
