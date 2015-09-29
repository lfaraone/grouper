from __future__ import unicode_literals

from django.db import models

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

    class Meta:
        managed = False
        db_table = 'users'
