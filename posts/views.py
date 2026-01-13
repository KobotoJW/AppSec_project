from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q, Count, Avg
from django.core.paginator import Paginator
from django.http import HttpResponseForbidden, JsonResponse
from django.views.decorators.http import require_http_methods, require_POST
from django.core.files.base import ContentFile
from django.utils import timezone

from .models import Post, Comment, Rating, ContentReport
from .forms import PostForm, CommentForm, RatingForm, ContentReportForm, SearchForm
from .utils import (
    rate_limit, log_security_event, get_client_ip,
    reencode_image, check_content_safety, require_role
)


@rate_limit('search', max_requests=100, time_window_minutes=60)
def feed(request):
    """
    Public feed visible to all users (guests and authenticated)
    Shows all non-deleted posts with search functionality
    Rate limited to prevent abuse: 100 searches per hour
    """
    search_form = SearchForm(request.GET or None)
    query = None
    
                               
    posts = Post.objects.filter(is_deleted=False).select_related('author').prefetch_related('comments', 'ratings')
    
                                                              
    if search_form.is_valid() and search_form.cleaned_data.get('query'):
        query = search_form.cleaned_data['query']
                                                                               
        posts = posts.filter(
            Q(content__icontains=query) | Q(author__email__icontains=query)
        )
        
                                            
        if request.user.is_authenticated:
            log_security_event(
                event_type='search',
                user=request.user,
                ip_address=get_client_ip(request),
                details={'query': query},
                request=request
            )
    
                                             
    posts = posts.annotate(
        comment_count=Count('comments', filter=Q(comments__is_deleted=False)),
        rating_avg=Avg('ratings__value')
    ).order_by('-created_at')                      
    
                                
    paginator = Paginator(posts, 10)                     
    
                                       
    page_number = request.GET.get('page', 1)
    try:
        page_number = int(page_number)
                                   
        if page_number < 1:
            page_number = 1
        elif page_number > 10000:                        
            page_number = 10000
    except (TypeError, ValueError):
        page_number = 1
    
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'search_form': search_form,
        'query': query,
        'is_feed': True
    }
    
    return render(request, 'posts/feed.html', context)


@login_required
@rate_limit('post_create', max_requests=10, time_window_minutes=60)                     
@require_http_methods(["GET", "POST"])
def create_post(request):
    """
    Create a new post (authenticated users only)
    With rate limiting and security checks
    """
    if request.method == 'POST':
        form = PostForm(request.POST, request.FILES)
        
        if form.is_valid():
                                  
            content = form.cleaned_data['content']
            is_safe, message = check_content_safety(content)
            
            if not is_safe:
                messages.error(request, f"Content validation failed: {message}")
                return render(request, 'posts/create_post.html', {'form': form})
            
            post = form.save(commit=False)
            post.author = request.user
            
                                       
            if post.image:
                try:
                                                                                    
                    reencoded = reencode_image(post.image)
                    filename = f"{post.id}.jpg"
                    post.image.save(filename, ContentFile(reencoded.read()), save=False)
                except Exception as e:
                    messages.error(request, f"Image processing failed: {str(e)}")
                    return render(request, 'posts/create_post.html', {'form': form})
            
            post.save()
            
                                
            log_security_event(
                event_type='post_created',
                user=request.user,
                ip_address=get_client_ip(request),
                details={'post_id': str(post.id), 'has_image': bool(post.image)},
                request=request
            )
            
            messages.success(request, 'Post created successfully!')
            return redirect('posts:post_detail', post_id=post.id)
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = PostForm()
    
    return render(request, 'posts/create_post.html', {'form': form})


def post_detail(request, post_id):
    """
    View post details with comments and ratings
    Accessible to all users (guests and authenticated)
    """
    post = get_object_or_404(Post, id=post_id, is_deleted=False)
    comments = post.comments.filter(is_deleted=False).select_related('author').order_by('created_at')
    
                           
    rating_stats = post.get_rating_stats()
    
                                               
    user_rating = None
    if request.user.is_authenticated:
        try:
            user_rating = Rating.objects.get(post=post, user=request.user)
        except Rating.DoesNotExist:
            pass
    
                                   
    comment_form = CommentForm() if request.user.is_authenticated else None
    rating_form = RatingForm(instance=user_rating) if request.user.is_authenticated else None
    
    context = {
        'post': post,
        'comments': comments,
        'comment_form': comment_form,
        'rating_form': rating_form,
        'rating_stats': rating_stats,
        'user_rating': user_rating,
        'can_delete': request.user.is_authenticated and (
            post.author == request.user or request.user.is_admin
        )
    }
    
    return render(request, 'posts/post_detail.html', context)


@login_required
@rate_limit('comment_add', max_requests=30, time_window_minutes=60)                        
@require_POST
def add_comment(request, post_id):
    """Add a comment to a post"""
    post = get_object_or_404(Post, id=post_id, is_deleted=False)
    form = CommentForm(request.POST)
    
    if form.is_valid():
                              
        content = form.cleaned_data['content']
        is_safe, message = check_content_safety(content)
        
        if not is_safe:
            messages.error(request, f"Comment validation failed: {message}")
            return redirect('posts:post_detail', post_id=post_id)
        
        comment = form.save(commit=False)
        comment.post = post
        comment.author = request.user
        comment.save()
        
                            
        log_security_event(
            event_type='comment_created',
            user=request.user,
            ip_address=get_client_ip(request),
            details={'post_id': str(post_id), 'comment_id': str(comment.id)},
            request=request
        )
        
        messages.success(request, 'Comment added successfully!')
    else:
        messages.error(request, 'Failed to add comment. Please check your input.')
    
    return redirect('posts:post_detail', post_id=post_id)


@login_required
@rate_limit('rating_add', max_requests=100, time_window_minutes=60)                       
@require_POST
def rate_post(request, post_id):
    """Rate a post (1-5 stars)"""
    post = get_object_or_404(Post, id=post_id, is_deleted=False)
    
                          
    rating, created = Rating.objects.get_or_create(
        post=post,
        user=request.user,
        defaults={'value': int(request.POST.get('value', 3))}
    )
    
    if not created:
                                
        rating.value = int(request.POST.get('value', rating.value))
        rating.save()
        messages.success(request, 'Rating updated!')
    else:
        messages.success(request, 'Rating added!')
    
                        
    log_security_event(
        event_type='post_rated',
        user=request.user,
        ip_address=get_client_ip(request),
        details={'post_id': str(post_id), 'rating': rating.value},
        request=request
    )
    
    return redirect('posts:post_detail', post_id=post_id)


@login_required
@require_POST
def delete_post(request, post_id):
    """
    Delete a post (soft delete)
    Users can delete their own posts, admins can delete any post
    """
    post = get_object_or_404(Post, id=post_id)
    
                       
    if post.author != request.user and not request.user.is_admin:
        return HttpResponseForbidden("You don't have permission to delete this post")
    
                 
    post.soft_delete(deleted_by_user=request.user)
    
                        
    log_security_event(
        event_type='post_deleted',
        user=request.user,
        ip_address=get_client_ip(request),
        details={
            'post_id': str(post_id),
            'post_author': post.author.email,
            'is_admin_action': request.user.is_admin
        },
        request=request
    )
    
    messages.success(request, 'Post deleted successfully!')
    return redirect('posts:feed')


@login_required
@require_POST
def delete_comment(request, comment_id):
    """
    Delete a comment (soft delete)
    Users can delete their own comments, admins can delete any comment
    """
    comment = get_object_or_404(Comment, id=comment_id)
    
                       
    if comment.author != request.user and not request.user.is_admin:
        return HttpResponseForbidden("You don't have permission to delete this comment")
    
    post_id = comment.post.id
    
                 
    comment.soft_delete(deleted_by_user=request.user)
    
                        
    log_security_event(
        event_type='comment_deleted',
        user=request.user,
        ip_address=get_client_ip(request),
        details={
            'comment_id': str(comment_id),
            'post_id': str(post_id),
            'comment_author': comment.author.email,
            'is_admin_action': request.user.is_admin
        },
        request=request
    )
    
    messages.success(request, 'Comment deleted successfully!')
    return redirect('posts:post_detail', post_id=post_id)


@login_required
@rate_limit('report_content', max_requests=10, time_window_minutes=60)
@require_http_methods(["GET", "POST"])
def report_content(request, content_type, content_id):
    """Report inappropriate content (post or comment)"""
    if content_type == 'post':
        content = get_object_or_404(Post, id=content_id, is_deleted=False)
        report_post = content
        report_comment = None
    elif content_type == 'comment':
        content = get_object_or_404(Comment, id=content_id, is_deleted=False)
        report_post = None
        report_comment = content
    else:
        return HttpResponseForbidden("Invalid content type")
    
    if request.method == 'POST':
        form = ContentReportForm(request.POST)
        if form.is_valid():
            report = form.save(commit=False)
            report.reporter = request.user
            report.post = report_post
            report.comment = report_comment
            report.save()
            
                                          
            if report_post:
                report_post.flag_count += 1
                if report_post.flag_count >= 3:                             
                    report_post.is_flagged = True
                report_post.save()
            
                                
            log_security_event(
                event_type='content_reported',
                user=request.user,
                ip_address=get_client_ip(request),
                details={
                    'content_type': content_type,
                    'content_id': str(content_id),
                    'reason': report.reason
                },
                request=request
            )
            
            messages.success(request, 'Content reported successfully. Our team will review it.')
            return redirect('posts:feed')
    else:
        form = ContentReportForm()
    
    context = {
        'form': form,
        'content_type': content_type,
        'content': content
    }
    return render(request, 'posts/report_content.html', context)


@require_role('admin')
@require_http_methods(["GET"])
def moderation_queue(request):
    """Admin view for moderating reported content"""
    pending_reports = ContentReport.objects.filter(
        status='pending'
    ).select_related('reporter', 'post', 'comment').order_by('-created_at')
    
    flagged_posts = Post.objects.filter(
        is_flagged=True, is_deleted=False
    ).select_related('author').order_by('-flag_count', '-created_at')
    
    context = {
        'pending_reports': pending_reports,
        'flagged_posts': flagged_posts
    }
    
    return render(request, 'posts/moderation_queue.html', context)


@require_role('admin')
@require_POST
def handle_report(request, report_id):
    """Admin action to handle a content report"""
    report = get_object_or_404(ContentReport, id=report_id)
    action = request.POST.get('action')                               
    
    if action == 'dismiss':
        report.status = 'dismissed'
        report.reviewed_by = request.user
        report.reviewed_at = timezone.now()
        report.save()
        messages.success(request, 'Report dismissed.')
        
    elif action == 'delete_content':
                                     
        if report.post:
            report.post.soft_delete(deleted_by_user=request.user)
        elif report.comment:
            report.comment.soft_delete(deleted_by_user=request.user)
        
        report.status = 'action_taken'
        report.reviewed_by = request.user
        report.reviewed_at = timezone.now()
        report.save()
        messages.success(request, 'Content deleted and report marked as resolved.')
    
                      
    log_security_event(
        event_type='report_handled',
        user=request.user,
        ip_address=get_client_ip(request),
        details={
            'report_id': str(report_id),
            'action': action,
            'content_type': 'post' if report.post else 'comment'
        },
        request=request
    )
    
    return redirect('posts:moderation_queue')


@require_role('admin')
@require_POST
def restore_content(request, content_type, content_id):
    """Admin action to restore soft-deleted content"""
    if content_type == 'post':
        content = get_object_or_404(Post, id=content_id)
        content.restore()
        messages.success(request, 'Post restored successfully.')
    elif content_type == 'comment':
        content = get_object_or_404(Comment, id=content_id)
        content.restore()
        messages.success(request, 'Comment restored successfully.')
    else:
        return HttpResponseForbidden("Invalid content type")
    
                      
    log_security_event(
        event_type='content_restored',
        user=request.user,
        ip_address=get_client_ip(request),
        details={
            'content_type': content_type,
            'content_id': str(content_id)
        },
        request=request
    )
    
    return redirect('posts:moderation_queue')
