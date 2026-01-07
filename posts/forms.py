from django import forms
from django.core.exceptions import ValidationError
from PIL import Image
from .models import Post, Comment, Rating, ContentReport


class PostForm(forms.ModelForm):
    """Form for creating posts with security validation"""
    
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    MAX_IMAGE_DIMENSION = 4096  # Max width/height in pixels
    
    class Meta:
        model = Post
        fields = ['content', 'image']
        widgets = {
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Share your thoughts...',
                'rows': 4,
                'maxlength': 5000
            }),
            'image': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': 'image/jpeg,image/png,image/gif,image/webp'
            })
        }
    
    def clean_content(self):
        """Validate and sanitize content"""
        content = self.cleaned_data.get('content', '').strip()
        if not content:
            raise ValidationError("Content cannot be empty")
        if len(content) > 5000:
            raise ValidationError("Content is too long (max 5000 characters)")
        return content
    
    def clean_image(self):
        """Validate image upload with security checks"""
        image = self.cleaned_data.get('image')
        if not image:
            return image
        
        # Check file size
        if image.size > self.MAX_FILE_SIZE:
            raise ValidationError(f"Image file too large (max {self.MAX_FILE_SIZE // (1024*1024)}MB)")
        
        # Check if it's actually an image
        try:
            img = Image.open(image)
            img.verify()  # Verify it's a valid image
            
            # Re-open for further checks (verify() closes the file)
            image.seek(0)
            img = Image.open(image)
            
            # Check dimensions
            width, height = img.size
            if width > self.MAX_IMAGE_DIMENSION or height > self.MAX_IMAGE_DIMENSION:
                raise ValidationError(f"Image dimensions too large (max {self.MAX_IMAGE_DIMENSION}x{self.MAX_IMAGE_DIMENSION})")
            
            # Check format is allowed
            if img.format.upper() not in ['JPEG', 'PNG', 'GIF', 'WEBP']:
                raise ValidationError("Invalid image format. Only JPEG, PNG, GIF, and WEBP are allowed")
            
        except Exception as e:
            raise ValidationError(f"Invalid image file: {str(e)}")
        
        # Reset file pointer
        image.seek(0)
        return image


class CommentForm(forms.ModelForm):
    """Form for creating comments"""
    
    class Meta:
        model = Comment
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Write a comment...',
                'rows': 3,
                'maxlength': 2000
            })
        }
    
    def clean_content(self):
        """Validate and sanitize comment content"""
        content = self.cleaned_data.get('content', '').strip()
        if not content:
            raise ValidationError("Comment cannot be empty")
        if len(content) > 2000:
            raise ValidationError("Comment is too long (max 2000 characters)")
        return content


class RatingForm(forms.ModelForm):
    """Form for rating posts"""
    
    class Meta:
        model = Rating
        fields = ['value']
        widgets = {
            'value': forms.RadioSelect(choices=[(i, f"{i} ★") for i in range(1, 6)])
        }
    
    def clean_value(self):
        """Validate rating value"""
        value = self.cleaned_data.get('value')
        if value is None:
            raise ValidationError("Please select a rating")
        if not (1 <= value <= 5):
            raise ValidationError("Rating must be between 1 and 5")
        return value


class ContentReportForm(forms.ModelForm):
    """Form for reporting inappropriate content"""
    
    class Meta:
        model = ContentReport
        fields = ['reason', 'description']
        widgets = {
            'reason': forms.Select(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Please provide additional details...',
                'rows': 4,
                'maxlength': 1000
            })
        }
    
    def clean_description(self):
        """Validate report description"""
        description = self.cleaned_data.get('description', '').strip()
        if len(description) > 1000:
            raise ValidationError("Description is too long (max 1000 characters)")
        return description


class SearchForm(forms.Form):
    """Form for searching posts with SQL injection protection"""
    
    query = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search posts...',
            'maxlength': 200
        })
    )
    
    def clean_query(self):
        """Sanitize search query"""
        query = self.cleaned_data.get('query', '').strip()
        if len(query) > 200:
            raise ValidationError("Search query is too long")
        # Django ORM will handle SQL injection protection
        return query
