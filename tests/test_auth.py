import pytest
from app.models import User
from app import db

def test_register_new_user(client, init_database):
    """Test successful registration of a new user."""
    response = client.post('/register', data={
        'username': 'newuser',
        'password': 'password'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Registration successful. Please log in.' in response.data
    user = User.query.filter_by(username='newuser').first()
    assert user is not None
    assert user.username == 'newuser'

def test_register_existing_username(client, init_database):
    """Test registration with an existing username."""
    # First, register a user
    client.post('/register', data={'username': 'testuser', 'password': 'password'}, follow_redirects=True)
    # Try to register the same username again
    response = client.post('/register', data={
        'username': 'testuser',
        'password': 'anotherpassword'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Username already exists.' in response.data
    user_count = User.query.filter_by(username='testuser').count()
    assert user_count == 1

def test_login_successful(client, init_database):
    """Test successful login with correct credentials."""
    # Register a user first
    client.post('/register', data={'username': 'loginuser', 'password': 'password'}, follow_redirects=True)

    response = client.post('/login', data={
        'username': 'loginuser',
        'password': 'password'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Login successful.' in response.data
    # Assuming redirect to dashboard, check for dashboard content
    assert b'Dashboard' in response.data # Generic dashboard marker

def test_login_incorrect_username(client, init_database):
    """Test login with an incorrect username."""
    client.post('/register', data={'username': 'realuser', 'password': 'password'}, follow_redirects=True)
    response = client.post('/login', data={
        'username': 'fakeuser',
        'password': 'password'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Invalid username or password.' in response.data
    assert b'Dashboard' not in response.data # Should not reach dashboard

def test_login_incorrect_password(client, init_database):
    """Test login with an incorrect password."""
    client.post('/register', data={'username': 'userpass', 'password': 'realpassword'}, follow_redirects=True)
    response = client.post('/login', data={
        'username': 'userpass',
        'password': 'fakepassword'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Invalid username or password.' in response.data
    assert b'Dashboard' not in response.data

def test_logout(client, init_database, auth_client):
    """Test successful logout."""
    auth_client.register_and_login(username='logoutuser', password='password')

    # Verify logged in by accessing a protected route (e.g., dashboard)
    response = client.get('/dashboard', follow_redirects=True)
    assert b'Logout' in response.data # Nav bar should show logout
    assert b'Dashboard' in response.data

    logout_response = auth_client.logout()
    assert logout_response.status_code == 200
    assert b'You have been logged out.' in logout_response.data
    assert b'Login' in logout_response.data # Nav bar should show login again

    # Verify logged out by trying to access dashboard again
    response_after_logout = client.get('/dashboard', follow_redirects=True)
    assert b'Login' in response_after_logout.data # Should be redirected to login
    assert b'Dashboard' not in response_after_logout.data # Should not see dashboard content
    assert b'Username' in response_after_logout.data # Login page check
    assert b'Password' in response_after_logout.data # Login page check
