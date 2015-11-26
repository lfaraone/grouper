from __future__ import unicode_literals

from datetime import datetime

from django.db import models
from django.db.models import Q

from django.contrib.auth.models import AbstractBaseUser

# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
#
# Also note: You'll have to insert the output of 'django-admin sqlcustom [app_label]'
# into your database.

from django.db import models


class AsyncNotifications(models.Model):
    key = models.CharField(max_length=128, blank=True, null=True)
    email = models.CharField(max_length=128)
    subject = models.CharField(max_length=256)
    body = models.TextField()
    send_after = models.DateTimeField()
    sent = models.BooleanField()

    class Meta:
        managed = False
        db_table = 'async_notifications'


class AuditLog(models.Model):
    log_time = models.DateTimeField()
    actor = models.ForeignKey('User', related_name="actor_set")
    on_user = models.ForeignKey('User', blank=True, null=True)
    on_group = models.ForeignKey('Group', blank=True, null=True)
    on_permission = models.ForeignKey('Permission', blank=True, null=True)
    action = models.CharField(max_length=64)
    description = models.TextField()

    class Meta:
        managed = False
        db_table = 'audit_log'


class AuditMember(models.Model):
    audit = models.ForeignKey('Audit')
    edge = models.ForeignKey('GroupEdge')
    status = models.CharField(max_length=8)

    class Meta:
        managed = False
        db_table = 'audit_members'


class Audit(models.Model):
    group = models.ForeignKey('Group')
    complete = models.BooleanField()
    started_at = models.DateTimeField()
    ends_at = models.DateTimeField()
    last_reminder_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'audits'


class Comment(models.Model):
    obj_type = models.IntegerField()
    obj_pk = models.IntegerField()
    user = models.ForeignKey('User')
    comment = models.TextField()
    created_on = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'comments'


class Counter(models.Model):
    name = models.TextField(unique=True)  # This field type is a guess.
    count = models.IntegerField()
    last_modified = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'counters'


class GroupEdge(models.Model):
    group = models.ForeignKey('Group')
    member_type = models.IntegerField()
    member_pk = models.IntegerField()
    expiration = models.DateTimeField(blank=True, null=True)
    active = models.BooleanField()
    field_role = models.SmallIntegerField(db_column='_role')  # Field renamed because it started with '_'.

    class Meta:
        managed = False
        db_table = 'group_edges'
        unique_together = (('group', 'member_type', 'member_pk'),)


class Group(models.Model):
    JOIN_CHOICES = (
        ("nobody", "Nobody"),
        ("canask", "Can ask"),
        ("canjoin", "Anyone can join"),
    )

    groupname = models.CharField(unique=True, max_length=32)
    description = models.TextField(blank=True, null=True)
    canjoin = models.CharField(max_length=7, blank=True, null=True, choices=JOIN_CHOICES)
    enabled = models.BooleanField()
    audit_id = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'groups'


class Permission(models.Model):
    name = models.CharField(unique=True, max_length=64)
    description = models.TextField()
    created_on = models.DateTimeField(auto_now=True)
    audited = models.BooleanField(default=False)

    class Meta:
        managed = False
        db_table = 'permissions'


class PermissionsMap(models.Model):
    permission = models.ForeignKey(Permission)
    group = models.ForeignKey(Group)
    argument = models.CharField(max_length=64, blank=True, null=True)
    granted_on = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'permissions_map'
        unique_together = (('permission', 'group', 'argument'),)


class PublicKey(models.Model):
    user = models.ForeignKey('User')
    key_type = models.CharField(max_length=32, blank=True, null=True)
    key_size = models.IntegerField(blank=True, null=True)
    public_key = models.TextField(unique=True)
    fingerprint = models.CharField(max_length=64)
    created_on = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'public_keys'


class RequestStatusChange(models.Model):
    request = models.ForeignKey('Request', blank=True, null=True)
    user = models.ForeignKey('User')
    from_status = models.CharField(max_length=9, blank=True, null=True)
    to_status = models.CharField(max_length=9)
    change_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'request_status_changes'


class Request(models.Model):
    requester = models.ForeignKey('User')
    requesting = models.ForeignKey(Group)
    on_behalf_obj_type = models.IntegerField()
    on_behalf_obj_pk = models.IntegerField()
    edge = models.ForeignKey(GroupEdge)
    requested_at = models.DateTimeField()
    status = models.CharField(max_length=9)
    changes = models.TextField()

    class Meta:
        managed = False
        db_table = 'requests'


class UserMetadata(models.Model):
    user = models.ForeignKey('User')
    data_key = models.CharField(max_length=64)
    data_value = models.CharField(max_length=64)
    last_modified = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'user_metadata'
        unique_together = (('user', 'data_key'),)

class User(AbstractBaseUser):
    username = models.CharField(unique=True, max_length=128)
    capabilities = models.IntegerField()
    enabled = models.BooleanField()
    role_user = models.BooleanField()

    USERNAME_FIELD = "username"

    def enable(self):
        self.enabled = True
        self.save(update_fields=['enabled'])

    def can_manage(self, group):
        """Determine if this user can manage the given group

        This returns true if this user object is a manager, owner, or np-owner of the given group.

        Args:
            group (Group): Group to check permissions against.

        Returns:
            bool: True or False on whether or not they can manage.
        """
        if not group:
            return False
        members = group.my_members()
        if self.my_role(members) in ("owner", "np-owner", "manager"):
            return True
        return False

    def disable(self, requester):
        for group in self.my_groups():
            group_obj = Group.objects.get(name=group.name)
            if group_obj:
                group_obj.revoke_member(
                    requester, "Account has been disabled."
                )

        self.enabled = False
        self.save(update_fields=['enabled'])
        Counter.incr(self.session, "updates")

    @property
    def user_admin(self):
        return Capabilities(self.capabilities).has("user_admin")

    @property
    def group_admin(self):
        return Capabilities(self.capabilities).has("group_admin")

    @property
    def permission_admin(self):
        return Capabilities(self.capabilities).has("permission_admin")

    def is_member(self, members):
        return ("User", self.name) in members

    def my_role(self, members):
        if self.group_admin:
            return "owner"
        member = members.get(("User", self.name))
        if not member:
            return None
        return GROUP_EDGE_ROLES[member.role]

    def set_metadata(self, key, value):
        if not re.match(PERMISSION_VALIDATION, key):
            raise ValueError('Metadata key does not match regex.')

        row = None
        for try_row in self.my_metadata():
            if try_row.data_key == key:
                row = try_row
                break

        if row:
            if value is None:
                row.delete()
            else:
                row.data_value = value
        else:
            if value is None:
                # Do nothing, a delete on a key that's not set
                return
            else:
                row = UserMetadata(user_id=self.id, data_key=key, data_value=value)
                row.save()

    def my_metadata(self):
        return UserMetadata.objects.filter(user_id=self).all()

    def my_public_keys(self):
        return PublicKey.objects.filter(user_id=self).all()

    def my_log_entries(self):
        return (AuditLog.objects.filter(on_user=self) | AuditLog.objects.filter(actor=self)).all()

    def has_permission(self, permission, argument=None):
        """See if this user has a given permission/argument

        This walks a user's permissions (local/direct only) and determines if they have the given
        permission. If an argument is specified, we validate if they have exactly that argument
        or if they have the wildcard ('*') argument.

        Args:
            permission (str): Name of permission to check for.
            argument (str, Optional): Name of argument to check for.

        Returns:
            bool: Whether or not this user fulfills the permission.
        """
        for perm in self.my_permissions():
            if perm.name != permission:
                continue
            if perm.argument == '*' or argument is None:
                return True
            if perm.argument == argument:
                return True
        return False

    def my_permissions(self):

        # TODO: Make this walk the tree, so we can get a user's entire set of permissions.
        now = datetime.utcnow()
        # permissions = Permission.objects.filter(permission_id = /
        return "XXX"
        permissions = self.session.query(
            Permission.name,
            PermissionMap.argument,
            PermissionMap.granted_on,
            Group,
        ).filter(
            PermissionMap.permission_id == Permission.id,
            PermissionMap.group_id == Group.id,
            GroupEdge.group_id == Group.id,
            GroupEdge.member_pk == self.id,
            GroupEdge.member_type == 0,
            GroupEdge.active == True,
            self.enabled == True,
            Group.enabled == True,
            or_(
                GroupEdge.expiration > now,
                GroupEdge.expiration == None
            )
        ).order_by(
            asc("name"), asc("argument"), asc("groupname")
        ).all()

        return permissions

    def my_creatable_permissions(self):
        '''
        Returns a list of permissions this user is allowed to create. Presently, this only counts
        permissions that a user has directly -- in other words, the 'create' permissions are not
        counted as inheritable.

        TODO: consider making these permissions inherited? This requires walking the graph, which
        is expensive.

        Returns a list of strings that are to be interpreted as glob strings. You should use the
        util function matches_glob.
        '''
        if self.permission_admin:
            return '*'

        # Someone can grant a permission if they are a member of a group that has a permission
        # of PERMISSION_GRANT with an argument that matches the name of a permission.
        return [
            permission.argument
            for permission in self.my_permissions()
            if permission.name == PERMISSION_CREATE
        ]

    def my_grantable_permissions(self):
        '''
        Returns a list of permissions this user is allowed to grant. Presently, this only counts
        permissions that a user has directly -- in other words, the 'grant' permissions are not
        counted as inheritable.

        TODO: consider making these permissions inherited? This requires walking the graph, which
        is expensive.

        Returns a list of tuples (Permission, argument) that the user is allowed to grant.
        '''
        all_permissions = {permission.name: permission
                           for permission in Permission.get_all(self.session)}
        if self.permission_admin:
            result = [(perm, '*') for perm in all_permissions.values()]
            return sorted(result, key=lambda x: x[0].name + x[1])

        # Someone can grant a permission if they are a member of a group that has a permission
        # of PERMISSION_GRANT with an argument that matches the name of a permission.
        result = []
        for permission in self.my_permissions():
            if permission.name != PERMISSION_GRANT:
                continue
            grantable = permission.argument.split('/', 1)
            if not grantable:
                continue
            for name, permission_obj in all_permissions.iteritems():
                if matches_glob(grantable[0], name):
                    result.append((permission_obj,
                                   grantable[1] if len(grantable) > 1 else '*', ))
        return sorted(result, key=lambda x: x[0].name + x[1])

    def my_groups(self):
        now = datetime.utcnow()
        groupedges = GroupEdge.objects.filter(
                Q(expiration__gt=now) | Q(expiration__eq=None),
                member_pk=self.id, member_type=0, active=True, group__enabled=True
            ).select_related("group")

        return [
                {
                    "name": groupedge.group.groupname,
                    "type": "Group",
                    "role": groupedge.field_role,
                } for groupedge in groupedges
        ]

    def my_requests_aggregate(self):
        """Returns all pending requests for this user to approve across groups."""
        members = self.session.query(
            label("type", literal(1)),
            label("id", Group.id),
            label("name", Group.groupname),
        ).union(self.session.query(
            label("type", literal(0)),
            label("id", User.id),
            label("name", User.username),
        )).subquery()

        now = datetime.utcnow()
        groups = self.session.query(
            label("id", Group.id),
            label("name", Group.groupname),
        ).filter(
            GroupEdge.group_id == Group.id,
            GroupEdge.member_pk == self.id,
            GroupEdge.active == True,
            GroupEdge._role.in_([1, 2]),
            self.enabled == True,
            Group.enabled == True,
            or_(
                GroupEdge.expiration > now,
                GroupEdge.expiration == None,
            )
        ).subquery()

        requests = self.session.query(
            Request.id,
            Request.requested_at,
            GroupEdge.expiration,
            label("role", GroupEdge._role),
            Request.status,
            label("requester", User.username),
            label("type", members.c.type),
            label("requesting", members.c.name),
            label("reason", Comment.comment),
            label("group_id", groups.c.id),
            label("groupname", groups.c.name),
        ).filter(
            Request.on_behalf_obj_pk == members.c.id,
            Request.on_behalf_obj_type == members.c.type,
            Request.requesting_id == groups.c.id,
            Request.requester_id == User.id,
            Request.status == "pending",
            Request.id == RequestStatusChange.request_id,
            RequestStatusChange.from_status == None,
            GroupEdge.id == Request.edge_id,
            Comment.obj_type == 3,
            Comment.obj_pk == RequestStatusChange.id,
        )

        return requests

    def my_open_audits(self):
        Audit.objects.filter(complete=False)
        self.session.query(Audit).filter(Audit.complete == False)
        now = datetime.utcnow()
        return self.session.query(
            label("groupname", Group.groupname),
            label("started_at", Audit.started_at),
            label("ends_at", Audit.ends_at),
        ).filter(
            Audit.group_id == Group.id,
            Audit.complete == False,
            GroupEdge.group_id == Group.id,
            GroupEdge.member_pk == self.id,
            GroupEdge.member_type == 0,
            GroupEdge.active == True,
            GroupEdge._role.in_(OWNER_ROLE_INDICES),
            self.enabled == True,
            Group.enabled == True,
            or_(
                GroupEdge.expiration > now,
                GroupEdge.expiration == None,
            )
        ).all()



    def __repr__(self):
        return "<%s: id=%s username=%s>" % (
            type(self).__name__, self.id, self.username)


    class Meta:
        managed = False
        db_table = 'users'
