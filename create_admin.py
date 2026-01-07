"""
Script to create an admin user for the secure content platform
"""
import os
import sys
import django

# Setup Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'appsec_project.settings')
django.setup()

from accounts.models import User

def create_admin():
    """Create an admin user if one doesn't exist"""
    
    # Check if admin exists
    if User.objects.filter(email='admin@example.com').exists():
        print("❌ Admin user already exists!")
        admin = User.objects.get(email='admin@example.com')
        print(f"   Email: {admin.email}")
        print(f"   Role: {admin.role}")
        print(f"   Active: {admin.is_active}")
        return
    
    # Create admin user
    admin = User.objects.create_user(
        email='admin@example.com',
        password='Admin123!@#'
    )
    admin.is_active = True
    admin.is_staff = True
    admin.is_superuser = True
    admin.role = 'admin'
    admin.save()
    
    print("✅ Admin user created successfully!")
    print(f"   Email: admin@example.com")
    print(f"   Password: Admin123!@#")
    print(f"   Role: {admin.role}")
    print("\n⚠️  IMPORTANT: Change this password after first login!")

def create_test_users():
    """Create test users for development"""
    
    test_users = [
        {'email': 'user1@example.com', 'password': 'User123!@#', 'role': 'user'},
        {'email': 'user2@example.com', 'password': 'User123!@#', 'role': 'user'},
    ]
    
    print("\n📝 Creating test users...")
    
    for user_data in test_users:
        if User.objects.filter(email=user_data['email']).exists():
            print(f"   ⚠️  {user_data['email']} already exists")
            continue
        
        user = User.objects.create_user(
            email=user_data['email'],
            password=user_data['password']
        )
        user.is_active = True
        user.role = user_data['role']
        user.save()
        
        print(f"   ✅ Created {user_data['email']} (password: {user_data['password']})")

if __name__ == '__main__':
    print("=" * 60)
    print("Secure Content Platform - Admin Setup")
    print("=" * 60)
    
    create_admin()
    
    choice = input("\nCreate test users for development? (y/n): ")
    if choice.lower() == 'y':
        create_test_users()
    
    print("\n" + "=" * 60)
    print("Setup complete! You can now:")
    print("1. Login at http://127.0.0.1:8000/accounts/login/")
    print("2. Access admin panel at http://127.0.0.1:8000/admin/")
    print("3. Start creating posts!")
    print("=" * 60)
