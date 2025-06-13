import pytest
import os
import tempfile
import sys

# Add project root to sys.path to allow importing 'app'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app as flask_app, db, models

@pytest.fixture(scope='session')
def app():
    """Session-wide test Flask application."""
    db_fd, db_path = tempfile.mkstemp(suffix='.sqlite')

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    flask_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "WTF_CSRF_ENABLED": False,  # Disable CSRF for testing forms
        "LOGIN_DISABLED": False, # Ensure login is enabled for tests
        "SERVER_NAME": "localhost.test", # Common for testing url_for
        "APPLICATION_ROOT": "/",
        "PREFERRED_URL_SCHEME": "http"
    })

    # Explicitly set template and static folder relative to project root
    # flask_app.template_folder = os.path.join(project_root, 'templates')
    # flask_app.static_folder = os.path.join(project_root, 'static')
    # Actually, Flask's root_path is the 'app' directory. Templates are '../templates' from there.
    flask_app.template_folder = os.path.join(flask_app.root_path, '..', 'templates')
    flask_app.static_folder = os.path.join(flask_app.root_path, '..', 'static')


    with flask_app.app_context():
        db.create_all()

    yield flask_app

    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture()
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture()
def runner(app):
    """A test CLI runner for the app."""
    return app.test_cli_runner()

@pytest.fixture(scope='function')
def init_database(app):
    """Clear and initialize the database for each test function."""
    with app.app_context():
        db.drop_all()
        db.create_all()
        # Add any initial data if necessary for all tests, e.g., a default admin
        # For now, we handle user creation within specific tests
    yield db # Can be used by tests to access db session

@pytest.fixture
def auth_client(client, init_database):
    """A test client that handles user registration and login for convenience."""

    class AuthActions:
        def __init__(self, client):
            self._client = client

        def login(self, username="testuser", password="password"):
            return self._client.post('/login', data=dict(
                username=username,
                password=password
            ), follow_redirects=True)

        def logout(self):
            return self._client.get('/logout', follow_redirects=True)

        def register(self, username="testuser", password="password", role=None):
            # Role assignment is handled by the backend logic (first user is admin)
            # This register function is simplified
            return self._client.post('/register', data=dict(
                username=username,
                password=password
            ), follow_redirects=True)

        def register_and_login(self, username="testuser", password="password"):
            self.register(username, password)
            return self.login(username, password)

    return AuthActions(client)
