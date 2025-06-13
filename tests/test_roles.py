import pytest
from app.models import User
from app import db

def test_first_user_is_admin(client, init_database):
    """Test that the first registered user is an admin."""
    client.post('/register', data={'username': 'adminuser', 'password': 'password'}, follow_redirects=True)
    admin_user = User.query.filter_by(username='adminuser').first()
    assert admin_user is not None
    assert admin_user.role == User.ROLE_ADMIN

def test_second_user_is_pilot(client, init_database):
    """Test that a subsequent registered user is a pilot."""
    # First user (admin)
    client.post('/register', data={'username': 'firstadmin', 'password': 'password'}, follow_redirects=True)
    # Second user (should be pilot)
    client.post('/register', data={'username': 'pilotuser', 'password': 'password'}, follow_redirects=True)

    pilot_user = User.query.filter_by(username='pilotuser').first()
    assert pilot_user is not None
    assert pilot_user.role == User.ROLE_PILOT

def test_admin_dashboard_access(client, init_database, auth_client):
    """Test that a logged-in admin user is redirected to the admin dashboard."""
    auth_client.register(username='mainadmin', password='password') # First user, becomes admin
    auth_client.login(username='mainadmin', password='password')

    response = client.get('/dashboard', follow_redirects=True)
    assert response.status_code == 200
    assert b'Admin Dashboard' in response.data
    assert b'User Management' in response.data # Admin specific content

def test_pilot_dashboard_access(client, init_database, auth_client):
    """Test that a logged-in pilot user is redirected to the pilot dashboard."""
    auth_client.register(username='admin1', password='password') # Admin
    auth_client.register(username='pilot1', password='password') # Pilot

    auth_client.login(username='pilot1', password='password')
    response = client.get('/dashboard', follow_redirects=True)
    assert response.status_code == 200
    assert b'Pilot Dashboard' in response.data
    assert b'Welcome to your Pilot Dashboard, pilot1!' in response.data
    assert b'User Management' not in response.data # Admin content should not be present

def test_unauthenticated_dashboard_access(client, init_database):
    """Test that an unauthenticated user trying to access /dashboard is redirected to login."""
    response = client.get('/dashboard', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data # Should be on login page
    assert b'Dashboard' not in response.data

def test_admin_can_access_user_list(client, init_database, auth_client):
    """Test that an admin can access the user list on their dashboard."""
    auth_client.register(username='adm', password='pwd') # Admin
    auth_client.register(username='usr1', password='pwd') # Pilot
    auth_client.login(username='adm', password='pwd')

    response = client.get('/dashboard', follow_redirects=True)
    assert b'User Management' in response.data
    assert b'usr1' in response.data # Check if the other user is listed

def test_admin_can_change_user_role(client, init_database, app, auth_client):
    """Test that an admin can change a user's role."""
    auth_client.register(username='theadmin', password='password') # Admin
    auth_client.register(username='thepilot', password='password') # Pilot
    auth_client.login(username='theadmin', password='password')

    # Verify pilot's initial role
    with app.app_context(): # Need app context to query DB directly
        pilot_user = User.query.filter_by(username='thepilot').first()
        assert pilot_user.role == User.ROLE_PILOT

    # Admin changes pilot's role to admin
    response = client.get(f'/admin/assign-role/{pilot_user.username}/{User.ROLE_ADMIN}', follow_redirects=True)
    assert response.status_code == 200
    assert b'Role for user thepilot updated to admin.' in response.data

    with app.app_context():
        updated_pilot_user = User.query.filter_by(username='thepilot').first()
        assert updated_pilot_user.role == User.ROLE_ADMIN

def test_pilot_cannot_access_assign_role_route(client, init_database, auth_client):
    """Test that a pilot cannot access the /admin/assign-role route."""
    auth_client.register(username='admin2', password='password') # Admin
    auth_client.register(username='pilot2', password='password') # Pilot
    auth_client.login(username='pilot2', password='password') # Login as pilot

    response = client.get(f'/admin/assign-role/admin2/{User.ROLE_PILOT}', follow_redirects=True)
    assert response.status_code == 200
    assert b'Unauthorized: Only admins can assign roles.' in response.data
    assert b'Admin Dashboard' not in response.data # Should not be on admin page
    assert b'Pilot Dashboard' in response.data # Should be redirected to their own dashboard

def test_pilot_does_not_see_user_management(client, init_database, auth_client):
    """Test that a pilot does not see the user list/role management on their dashboard."""
    auth_client.register(username='admin3', password='password') # Admin
    auth_client.register(username='pilot3', password='password') # Pilot
    auth_client.login(username='pilot3', password='password')

    response = client.get('/dashboard', follow_redirects=True)
    assert response.status_code == 200
    assert b'Pilot Dashboard' in response.data
    assert b'User Management' not in response.data
    assert b'admin3' not in response.data # Should not see other users listed
