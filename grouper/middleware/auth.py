from django.contrib.auth import backends, middleware
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
import logging

from ..frontend.util import normalize_auth_header


class EmailHeaderMiddleware(middleware.RemoteUserMiddleware):
    header = normalize_auth_header(settings.USER_AUTH_HEADER)


class EmailHeaderBackend(backends.RemoteUserBackend):
    """Custom backend that validates username is an email."""
    def authenticate(self, remote_user):
        """Override default to return None if username is invalid."""
        if not remote_user:
            return
        username = self.clean_username(remote_user)
        if not username:
            return

        return super(EmailHeaderBackend, self).authenticate(remote_user)

    def clean_username(self, username):
        """Makes sure that the username is a valid email address."""
        validator = EmailValidator()
        try:
            validator(username)  # If invalid, this will raise a ValidationError
        except ValidationError as err:
            return None
        else:
            return username

    def configure_user(self, user):
        """Make all new users superusers and staff"""
        user.save()
        return user
