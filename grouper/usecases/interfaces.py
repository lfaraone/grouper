"""Interfaces used by use cases to talk to backend services.

Defines general interfaces to use to talk to backend application services (storage, authorization,
user, group, permission, and so forth) that are shared among multiple use cases.  Also defines the
exceptions they throw, if needed.

Do not define UI interfaces to talk to frontends here.  There should be a one-to-one correspondance
between UI interfaces and use cases, so the UI interface is defined in the same file with the use
case.

By convention, all class names here end in Interface or Exception.
"""

from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING

from six import with_metaclass

if TYPE_CHECKING:
    from grouper.entities.audit_log_entry import AuditLogEntry
    from grouper.entities.group_request import GroupRequestStatus, UserGroupRequest
    from grouper.entities.pagination import PaginatedList, Pagination
    from grouper.entities.permission import Permission, PermissionAccess
    from grouper.entities.permission_grant import (
        GroupPermissionGrant,
        PermissionGrant,
        ServiceAccountPermissionGrant,
    )
    from grouper.usecases.authorization import Authorization
    from grouper.usecases.list_permissions import ListPermissionsSortKey
    from typing import ContextManager, List, Optional


class AuditLogInterface(with_metaclass(ABCMeta, object)):
    """Abstract base class for the audit log."""

    @abstractmethod
    def log_create_service_account_from_disabled_user(self, user, authorization):
        # type: (str, Authorization) -> None
        pass

    @abstractmethod
    def log_create_permission(self, permission, authorization):
        # type: (str, Authorization) -> None
        pass

    @abstractmethod
    def log_disable_permission(self, permission, authorization):
        # type: (str, Authorization) -> None
        pass

    @abstractmethod
    def log_disable_user(self, username, authorization):
        # type: (str, Authorization) -> None
        pass

    @abstractmethod
    def log_enable_service_account(self, user, owner, authorization):
        # type: (str, str, Authorization) -> None
        pass

    @abstractmethod
    def log_user_group_request_status_change(self, request, status, authorization):
        # type: (UserGroupRequest, GroupRequestStatus, Authorization) -> None
        pass

    @abstractmethod
    def entries_affecting_permission(self, permission, limit):
        # type: (str, int) -> List[AuditLogEntry]
        pass


class GroupRequestInterface(with_metaclass(ABCMeta, object)):
    """Abstract base class for requests for group membership."""

    @abstractmethod
    def cancel_all_requests_for_user(self, user, reason, authorization):
        # type: (str, str, Authorization) -> None
        pass


class PermissionInterface(with_metaclass(ABCMeta, object)):
    """Abstract base class for permission operations and queries."""

    @abstractmethod
    def disable_permission(self, name, authorization):
        # type: (str, Authorization) -> None
        pass

    @abstractmethod
    def group_grants_for_permission(self, name):
        # type: (str) -> List[GroupPermissionGrant]
        pass

    @abstractmethod
    def service_account_grants_for_permission(self, name):
        # type: (str) -> List[ServiceAccountPermissionGrant]
        pass

    @abstractmethod
    def is_system_permission(self, name):
        # type: (str) -> bool
        pass

    @abstractmethod
    def list_permissions(self, pagination, audited_only):
        # type: (Pagination[ListPermissionsSortKey], bool) -> PaginatedList[Permission]
        pass

    @abstractmethod
    def permission(self, name):
        # type: (str) -> Optional[Permission]
        pass

    @abstractmethod
    def permission_exists(self, name):
        # type: (str) -> bool
        pass


class ServiceAccountInterface(with_metaclass(ABCMeta, object)):
    """Abstract base class for service account operations and queries."""

    @abstractmethod
    def create_service_account_from_disabled_user(self, user, authorization):
        # type: (str, Authorization) -> None
        pass

    @abstractmethod
    def enable_service_account(self, user, owner, authorization):
        # type: (str, str, Authorization) -> None
        pass


class TransactionInterface(with_metaclass(ABCMeta, object)):
    """Abstract base class for starting and committing transactions."""

    def transaction(self):
        # type: () -> ContextManager[None]
        pass


class UserInterface(with_metaclass(ABCMeta, object)):
    """Abstract base class for user operations and queries."""

    @abstractmethod
    def disable_user(self, user, authorization):
        # type: (str, Authorization) -> None
        pass

    @abstractmethod
    def groups_of_user(self, user):
        # type: (str) -> List[str]
        pass

    @abstractmethod
    def permission_access_for_user(self, user, permission):
        # type: (str, str) -> PermissionAccess
        pass

    @abstractmethod
    def permission_grants_for_user(self, user):
        # type: (str) -> List[PermissionGrant]
        pass

    @abstractmethod
    def user_can_create_permissions(self, user):
        # type: (str) -> bool
        pass

    @abstractmethod
    def user_is_permission_admin(self, user):
        # type: (str) -> bool
        pass

    @abstractmethod
    def user_is_user_admin(self, user):
        # type: (str) -> bool
        pass
