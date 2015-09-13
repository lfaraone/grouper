from django.shortcuts import redirect, render
from django.http import HttpResponse

# Create your views here.

from datetime import datetime, timedelta
import operator

from expvar.stats import stats
from tornado.web import RequestHandler

from sqlalchemy import union_all
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import label, literal

import sshpubkey

from ..audit import assert_controllers_are_auditors, assert_can_join, UserNotAuditor
from ..constants import (
    PERMISSION_GRANT, PERMISSION_CREATE, PERMISSION_AUDITOR, AUDIT_MANAGER, AUDIT_VIEWER
)

from .forms import (
    AuditCreateForm,
    GroupAddForm,
    GroupCreateForm,
    GroupEditForm,
    GroupEditMemberForm,
    GroupJoinForm,
    GroupRemoveForm,
    GroupRequestModifyForm,
    PermissionCreateForm,
    PermissionGrantForm,
    PublicKeyForm,
    UsersPublicKeyForm,
)
from ..graph import NoSuchUser, NoSuchGroup
from ..models import (
    User, Group, Request, PublicKey, Permission, PermissionMap, AuditLog, GroupEdge, Counter,
    GROUP_JOIN_CHOICES, REQUEST_STATUS_CHOICES, GROUP_EDGE_ROLES, OBJ_TYPES,
    get_all_groups, get_all_users,
    get_user_or_group, Audit, AuditMember, AUDIT_STATUS_CHOICES,
)
from .settings import settings
from .util import ensure_audit_security, Alert, test_reserved_names, GrouperView
from ..util import matches_glob


class Index(GrouperView):
    def get(self, request):
        # For now, redirect to viewing your own profile. TODO: maybe have a
        # Grouper home page where you can maybe do stuff?
        user = self.current_user
        return redirect("/users/{}".format(user.username))


class Search(GrouperView):
    def get(self, request):
        query = request.GET.get("query", "")
        offset = int(request.GET.get("offset", 0))
        limit = int(request.GET.get("limit", 100))
        if limit > 9000:
            limit = 9000

        groups = self.session.query(
            label("type", literal("Group")),
            label("id", Group.id),
            label("name", Group.groupname)
        ).filter(
            Group.enabled == True,
            Group.groupname.like("%{}%".format(query))
        ).subquery()

        users = self.session.query(
            label("type", literal("User")),
            label("id", User.id),
            label("name", User.username)
        ).filter(
            User.enabled == True,
            User.username.like("%{}%".format(query))
        ).subquery()

        results_query = self.session.query(
            "type", "id", "name"
        ).select_entity_from(
            union_all(users.select(), groups.select())
        )
        total = results_query.count()
        results = results_query.offset(offset).limit(limit).all()

        if len(results) == 1:
            result = results[0]
            return redirect(("/{}s/{}".format(result.type.lower(), result.name)))

        return self.render(request, "search.html", results=results, search_query=query,
                    offset=offset, limit=limit, total=total)


class UserView(GrouperView):
    def get(self, request, user_id=None, name=None):
        #self.handle_refresh()
        user = User.get(self.session, user_id, name)
        if user_id is not None:
            user = self.session.query(User).filter_by(id=user_id).scalar()
        else:
            user = self.session.query(User).filter_by(username=name).scalar()

        if not user:
            return HttpResponse("404") # XXX(lfaraone)

        can_control = False
        if (user.name == self.current_user.name) or self.current_user.user_admin:
            can_control = True

        if user.id == self.current_user.id:
            num_pending_requests = self.current_user.my_requests_aggregate().count()
        else:
            num_pending_requests = None

        try:
            user_md = self.graph.get_user_details(user.name)
        except NoSuchUser:
            # Either user is probably very new, so they have no metadata yet, or
            # they're disabled, so we've excluded them from the in-memory graph.
            user_md = {}

        open_audits = user.my_open_audits()
        groups = user.my_groups()
        public_keys = user.my_public_keys()
        permissions = user_md.get('permissions', [])
        log_entries = user.my_log_entries()
        return self.render(request, "user.html", user=user, groups=groups, public_keys=public_keys,
                    can_control=can_control, permissions=permissions,
                    log_entries=log_entries, num_pending_requests=num_pending_requests,
                    open_audits=open_audits)


class PermissionsCreate(GrouperView):
    def get(self, request):
        can_create = self.current_user.my_creatable_permissions()
        if not can_create:
            raise PermissionDenied

        return self.render(request, 
            "permission-create.html",
            form=PermissionCreateForm(),
            can_create=can_create,
        )

    def post(self, request):
        can_create = self.current_user.my_creatable_permissions()
        if not can_create:
            raise PermissionDenied

        form = PermissionCreateForm(request.POST)
        if not form.validate():
            return self.render(request, 
                "permission-create.html", form=form,
                alerts=self.get_form_alerts(form.errors)
            )

        # A user is allowed to create a permission if the name matches any of the globs that they
        # are given access to via PERMISSION_CREATE, as long as the permission does not match a
        # reserved name. (Unless specifically granted.)
        allowed = False
        for creatable in can_create:
            if matches_glob(creatable, form.data["name"]):
                allowed = True

        for failure_message in test_reserved_names(form.data["name"]):
            form.name.errors.append(failure_message)

        if not allowed:
            form.name.errors.append(
                "Permission name does not match any of your allowed patterns."
            )

        if form.name.errors:
            return self.render(request, 
                "permission-create.html", form=form,
                alerts=self.get_form_alerts(form.errors),
            )

        permission = Permission(name=form.data["name"], description=form.data["description"])
        try:
            permission.add(self.session)
            self.session.flush()
        except IntegrityError:
            self.session.rollback()
            form.name.errors.append(
                "Name already in use. Permissions must be unique."
            )
            return self.render(request, 
                "permission-create.html", form=form, can_create=can_create,
                alerts=self.get_form_alerts(form.errors),
            )

        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'create_permission',
                     'Created permission.', on_permission_id=permission.id)

        # No explicit refresh because handler queries SQL.
        return redirect("/permissions/{}".format(permission.name))


class PermissionDisableAuditing(GrouperView):
    def post(self, request, user_id=None, name=None):
        if not self.current_user.permission_admin:
            raise PermissionDenied

        permission = Permission.get(self.session, name)
        if not permission:
            # XXX(lfaraone)
            return HttpResponse("404")

        permission.disable_auditing()
        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'disable_auditing',
                     'Disabled auditing.', on_permission_id=permission.id)

        # No explicit refresh because handler queries SQL.
        return redirect("/permissions/{}".format(permission.name))


class PermissionEnableAuditing(GrouperView):
    def post(self, request, name=None):
        if not self.current_user.permission_admin:
            raise PermissionDenied

        permission = Permission.get(self.session, name)
        if not permission:
            # XXX(lfaraone)
            return HttpResponse("404")

        permission.enable_auditing()
        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'enable_auditing',
                     'Enabled auditing.', on_permission_id=permission.id)

        # No explicit refresh because handler queries SQL.
        return redirect("/permissions/{}".format(permission.name))


class PermissionsGrant(GrouperView):
    def get(self, request, name=None):
        grantable = self.current_user.my_grantable_permissions()
        if not grantable:
            raise PermissionDenied

        group = Group.get(self.session, None, name)
        if not group:
            # XXX(lfaraone)
            return HttpResponse("404")

        form = PermissionGrantForm()
        form.permission.choices = [["", "(select one)"]]
        for perm in grantable:
            grantable = "{} ({})".format(perm[0].name, perm[1])
            form.permission.choices.append([perm[0].name, grantable])

        return self.render(request, 
            "permission-grant.html", form=form, group=group,
        )

    def post(self, request, name=None):
        grantable = self.current_user.my_grantable_permissions()
        if not grantable:
            raise PermissionDenied

        group = Group.get(self.session, None, name)
        if not group:
            # XXX(lfaraone)
            return HttpResponse("404")

        form = PermissionGrantForm(request.POST)
        form.permission.choices = [["", "(select one)"]]
        for perm in grantable:
            grantable_str = "{} ({})".format(perm[0].name, perm[1])
            form.permission.choices.append([perm[0].name, grantable_str])

        if not form.validate():
            return self.render(request, 
                "permission-grant.html", form=form, group=group,
                alerts=self.get_form_alerts(form.errors)
            )

        permission = Permission.get(self.session, form.data["permission"])
        if not permission:
            # XXX(lfaraone)
            return HttpResponse("404")

        allowed = False
        for perm in grantable:
            if perm[0].name == permission.name:
                if matches_glob(perm[1], form.data["argument"]):
                    allowed = True
        if not allowed:
            form.argument.errors.append(
                "You do not have grant authority over that permission/argument combination."
            )
            return self.render(request, 
                "permission-grant.html", form=form, group=group,
                alerts=self.get_form_alerts(form.errors),
            )

        # If the permission is audited, then see if the subtree meets auditing requirements.
        if permission.audited:
            fail_message = ("Permission is audited and this group (or a subgroup) contains " +
                            "owners, np-owners, or managers who have not received audit training.")
            try:
                permission_ok = assert_controllers_are_auditors(group)
            except UserNotAuditor as e:
                permission_ok = False
                fail_message = e
            if not permission_ok:
                form.permission.errors.append(fail_message)
                return self.render(request, 
                    "permission-grant.html", form=form, group=group,
                    alerts=self.get_form_alerts(form.errors),
                )

        try:
            group.grant_permission(permission, argument=form.data["argument"])
        except IntegrityError:
            form.argument.errors.append(
                "Permission and Argument already mapped to this group."
            )
            return self.render(request, 
                "permission-grant.html", form=form, group=group,
                alerts=self.get_form_alerts(form.errors),
            )

        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'grant_permission',
                     'Granted permission with argument: {}'.format(form.data["argument"]),
                     on_permission_id=permission.id, on_group_id=group.id)

        return redirect("/groups/{}?refresh=yes".format(group.name))


class PermissionsRevoke(GrouperView):
    def get(self, request, name=None, mapping_id=None):
        grantable = self.current_user.my_grantable_permissions()
        if not grantable:
            raise PermissionDenied

        mapping = PermissionMap.get(self.session, id=mapping_id)
        if not mapping:
            # XXX(lfaraone)
            return HttpResponse("404")

        allowed = False
        for perm in grantable:
            if perm[0].name == mapping.permission.name:
                if matches_glob(perm[1], mapping.argument):
                    allowed = True
        if not allowed:
            raise PermissionDenied

        return self.render(request, "permission-revoke.html", mapping=mapping)

    def post(self, request, name=None, mapping_id=None):
        grantable = self.current_user.my_grantable_permissions()
        if not grantable:
            raise PermissionDenied

        mapping = PermissionMap.get(self.session, id=mapping_id)
        if not mapping:
            return HttpResponse("404") # XXX(lfaraone)

        allowed = False
        for perm in grantable:
            if perm[0].name == mapping.permission.name:
                if matches_glob(perm[1], mapping.argument):
                    allowed = True
        if not allowed:
            raise PermissionDenied

        permission = mapping.permission
        group = mapping.group

        mapping.delete(self.session)
        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'revoke_permission',
                     'Revoked permission with argument: {}'.format(mapping.argument),
                     on_group_id=group.id, on_permission_id=permission.id)

        return redirect(('/groups/{}?refresh=yes'.format(group.name)))


class PermissionsView(GrouperView):
    '''
    Controller for viewing the major permissions list. There is no privacy here; the existence of
    a permission is public.
    '''
    def get(self, request, audited_only=False):
        offset = int(request.GET.get("offset", 0))
        limit = int(request.GET.get("limit", 100))
        audited_only = bool(int(request.GET.get("audited", 0)))
        if limit > 9000:
            limit = 9000

        permissions = self.graph.get_permissions(audited=audited_only)
        total = len(permissions)
        permissions = permissions[offset:offset + limit]

        can_create = self.current_user.my_creatable_permissions()

        return self.render(request, 
            "permissions.html", permissions=permissions, offset=offset, limit=limit, total=total,
            can_create=can_create, audited_permissions=audited_only
        )


class PermissionView(GrouperView):
    def get(self, request, name=None):
        # TODO: use cached data instead, add refresh to appropriate redirects.
        permission = Permission.get(self.session, name)
        if not permission:
            return HttpResponse("404") # XXX(lfaraone)

        can_delete = self.current_user.permission_admin
        mapped_groups = permission.get_mapped_groups()
        log_entries = permission.my_log_entries()

        return self.render(request, 
            "permission.html", permission=permission, can_delete=can_delete,
            mapped_groups=mapped_groups, log_entries=log_entries,
        )


class UsersView(GrouperView):
    def get(self, request):
        # TODO: use cached users instead.
        offset = int(request.GET.get("offset", 0))
        limit = int(request.GET.get("limit", 100))
        enabled = bool(int(request.GET.get("enabled", 1)))
        if limit > 9000:
            limit = 9000

        users = (
            self.session.query(User)
            .filter(User.enabled == enabled)
            .order_by(User.username)
        )
        total = users.count()
        users = users.offset(offset).limit(limit).all()

        return self.render(request, 
            "users.html", users=users, offset=offset, limit=limit, total=total,
            enabled=enabled,
        )


class UsersPublicKey(GrouperView):
    @ensure_audit_security(u'public_keys')
    def get(self, request):
        form = UsersPublicKeyForm(request.POST)

        user_key_list = self.session.query(
            PublicKey,
            User,
        ).filter(
            User.id == PublicKey.user_id,
        )

        if not form.validate():
            user_key_list = user_key_list.filter(User.enabled == bool(form.enabled.default))

            total = user_key_list.count()
            user_key_list = user_key_list.offset(form.offset.default).limit(form.limit.default)

            return self.render(request, "users-publickey.html", user_key_list=user_key_list, total=total,
                    form=form, alerts=self.get_form_alerts(form.errors))

        user_key_list = user_key_list.filter(User.enabled == bool(form.enabled.data))

        if form.fingerprint.data:
            user_key_list = user_key_list.filter(PublicKey.fingerprint == form.fingerprint.data)

        if form.sort_by.data == "size":
            user_key_list = user_key_list.order_by(PublicKey.key_size.desc())
        elif form.sort_by.data == "type":
            user_key_list = user_key_list.order_by(PublicKey.key_type.desc())
        elif form.sort_by.data == "age":
            user_key_list = user_key_list.order_by(PublicKey.created_on.asc())
        elif form.sort_by.data == "user":
            user_key_list = user_key_list.order_by(User.username.desc())

        total = user_key_list.count()
        user_key_list = user_key_list.offset(form.offset.data).limit(form.limit.data)

        return self.render(request, "users-publickey.html", user_key_list=user_key_list, total=total, form=form)


class UserEnable(GrouperView):
    def post(self, request, user_id=None, name=None):
        if not self.current_user.user_admin:
            raise PermissionDenied

        user = User.get(self.session, user_id, name)
        if not user:
            return HttpResponse("404") # XXX(lfaraone)

        user.enable()
        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'enable_user',
                     'Enabled user.', on_user_id=user.id)

        return redirect(("/users/{}?refresh=yes".format(user.name)))


class UserDisable(GrouperView):
    def post(self, request, user_id=None, name=None):

        if not self.current_user.user_admin:
            raise PermissionDenied

        user = User.get(self.session, user_id, name)
        if not user:
            return HttpResponse("404") # XXX(lfaraone)

        user.disable(self.current_user)
        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'disable_user',
                     'Disabled user.', on_user_id=user.id)

        return redirect("/users/{}?refresh=yes".format(user.name))


class UserRequests(GrouperView):
    """Handle list all pending requests for a single user."""
    def get(self, request):
        offset = int(request.GET.get("offset", 0))
        limit = int(request.GET.get("limit", 100))
        if limit > 9000:
            limit = 9000

        requests = self.current_user.my_requests_aggregate().order_by(Request.requested_at.desc())

        total = requests.count()
        requests = requests.offset(offset).limit(limit)

        return self.render(request, "user-requests.html", requests=requests, offset=offset, limit=limit,
                total=total)


class GroupView(GrouperView):
    def get(self, request, group_id=None, name=None):
        self.handle_refresh()
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        grantable = self.current_user.my_grantable_permissions()

        try:
            group_md = self.graph.get_group_details(group.name)
        except NoSuchGroup:
            # Very new group with no metadata yet, or it has been disabled and
            # excluded from in-memory cache.
            group_md = {}

        members = group.my_members()
        groups = group.my_groups()
        permissions = group_md.get('permissions', [])
        audited = group_md.get('audited', False)
        log_entries = group.my_log_entries()
        num_pending = group.my_requests("pending").count()

        # Add mapping_id to permissions structure
        my_permissions = group.my_permissions()
        for perm_up in permissions:
            for perm_direct in my_permissions:
                if (perm_up['permission'] == perm_direct.name
                        and perm_up['argument'] == perm_direct.argument):
                    perm_up['mapping_id'] = perm_direct.mapping_id
                    break

        alerts = []
        self_pending = group.my_requests("pending", user=self.current_user).count()
        if self_pending:
            alerts.append(Alert('info', 'You have a pending request to join this group.', None))

        return self.render(request, 
            "group.html", group=group, members=members, groups=groups,
            num_pending=num_pending, alerts=alerts, permissions=permissions,
            log_entries=log_entries, grantable=grantable, audited=audited,
            statuses=AUDIT_STATUS_CHOICES,
        )


class GroupEditMember(GrouperView):
    def get(self, request, group_id=None, name=None, name2=None, member_type=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        if self.current_user.name == name2:
            raise PermissionDenied

        members = group.my_members()
        my_role = self.current_user.my_role(members)
        if my_role not in ("manager", "owner", "np-owner"):
            raise PermissionDenied

        member = members.get((member_type.capitalize(), name2), None)
        if not member:
            return HttpResponse("404") # XXX(lfaraone)

        edge = GroupEdge.get(
            self.session,
            group_id=group.id,
            member_type=OBJ_TYPES[member.type],
            member_pk=member.id,
        )
        if not edge:
            return HttpResponse("404") # XXX(lfaraone)

        form = GroupEditMemberForm(request.POST)
        form.role.choices = [["member", "Member"]]
        if my_role in ("owner", "np-owner"):
            form.role.choices.append(["manager", "Manager"])
            form.role.choices.append(["owner", "Owner"])
            form.role.choices.append(["np-owner", "No-Permissions Owner"])

        form.role.data = edge.role
        form.expiration.data = edge.expiration.strftime("%m/%d/%Y") if edge.expiration else None

        return self.render(request, 
            "group-edit-member.html", group=group, member=member, edge=edge, form=form,
        )

    def post(self, request, group_id=None, name=None, name2=None, member_type=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        if self.current_user.name == name2:
            raise PermissionDenied

        members = group.my_members()
        my_role = self.current_user.my_role(members)
        if my_role not in ("manager", "owner", "np-owner"):
            raise PermissionDenied

        member = members.get((member_type.capitalize(), name2), None)
        if not member:
            return HttpResponse("404") # XXX(lfaraone)

        if member.type == "Group":
            user_or_group = Group.get(self.session, member.id)
        else:
            user_or_group = User.get(self.session, member.id)
        if not user_or_group:
            return HttpResponse("404") # XXX(lfaraone)

        edge = GroupEdge.get(
            self.session,
            group_id=group.id,
            member_type=OBJ_TYPES[member.type],
            member_pk=member.id,
        )
        if not edge:
            return HttpResponse("404") # XXX(lfaraone)

        form = GroupEditMemberForm(request.POST)
        form.role.choices = [["member", "Member"]]
        if my_role in ("owner", "np-owner"):
            form.role.choices.append(["manager", "Manager"])
            form.role.choices.append(["owner", "Owner"])
            form.role.choices.append(["np-owner", "No-Permissions Owner"])

        if not form.validate():
            return self.render(request, 
                "group-edit-member.html", group=group, member=member, edge=edge, form=form,
                alerts=self.get_form_alerts(form.errors),
            )

        fail_message = 'This join is denied with this role at this time.'
        try:
            user_can_join = assert_can_join(group, user_or_group, role=form.data["role"])
        except UserNotAuditor as e:
            user_can_join = False
            fail_message = e
        if not user_can_join:
            return self.render(request, 
                "group-edit-member.html", form=form, group=group, member=member, edge=edge,
                alerts=[
                    Alert('danger', fail_message, 'Audit Policy Enforcement')
                ]
            )

        expiration = None
        if form.data["expiration"]:
            expiration = datetime.strptime(form.data["expiration"], "%m/%d/%Y")

        group.edit_member(self.current_user, user_or_group, form.data["reason"],
                          role=form.data["role"], expiration=expiration)

        return redirect("/groups/{}?refresh=yes".format(group.name))


class GroupRequestUpdate(GrouperView):
    def get(self, request, request_id, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        members = group.my_members()
        my_role = self.current_user.my_role(members)
        if my_role not in ("manager", "owner", "np-owner"):
            raise PermissionDenied

        request = self.session.query(Request).filter_by(id=request_id).scalar()
        if not request:
            return HttpResponse("404") # XXX(lfaraone)

        form = GroupRequestModifyForm(request.POST)
        form.status.choices = self._get_choices(request.status)


        updates = request.my_status_updates()

        return self.render(request, 
            "group-request-update.html", group=group, request=request,
            members=members, form=form, statuses=REQUEST_STATUS_CHOICES, updates=updates
        )

    def post(self, request, request_id, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        members = group.my_members()
        my_role = self.current_user.my_role(members)
        if my_role not in ("manager", "owner", "np-owner"):
            raise PermissionDenied

        request = self.session.query(Request).filter_by(id=request_id).scalar()
        if not request:
            return HttpResponse("404") # XXX(lfaraone)

        form = GroupRequestModifyForm(request.POST)
        form.status.choices = self._get_choices(request.status)

        updates = request.my_status_updates()

        if not form.validate():
            return self.render(request, 
                "group-request-update.html", group=group, request=request,
                members=members, form=form, alerts=self.get_form_alerts(form.errors),
                statuses=REQUEST_STATUS_CHOICES, updates=updates
            )

        # We have to test this here, too, to ensure that someone can't sneak in with a pending
        # request that used to be allowed.
        if form.data["status"] != "cancelled":
            fail_message = 'This join is denied with this role at this time.'
            try:
                user_can_join = assert_can_join(request.requesting, request.get_on_behalf(),
                                                role=request.edge.role)
            except UserNotAuditor as e:
                user_can_join = False
                fail_message = e
            if not user_can_join:
                return self.render(request, 
                    "group-request-update.html", group=group, request=request,
                    members=members, form=form, statuses=REQUEST_STATUS_CHOICES, updates=updates,
                    alerts=[
                        Alert('danger', fail_message, 'Audit Policy Enforcement')
                    ]
                )

        request.update_status(
            self.current_user,
            form.data["status"],
            form.data["reason"]
        )
        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'update_request',
                     'Updated request to status: {}'.format(form.data["status"]),
                     on_group_id=group.id, on_user_id=request.requester.id)

        # No explicit refresh because handler queries SQL.
        if form.data['redirect_aggregate']:
            return redirect("/user/requests")
        else:
            return redirect("/groups/{}/requests".format(group.name))

    def _get_choices(self, current_status):
        return [["", ""]] + [
            [status] * 2
            for status in REQUEST_STATUS_CHOICES[current_status]
        ]


class GroupRequests(GrouperView):
    def get(self, request, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        status = request.GET.get("status", None)
        offset = int(request.GET.get("offset", 0))
        limit = int(request.GET.get("limit", 100))
        if limit > 9000:
            limit = 9000

        requests = group.my_requests(status).order_by(
            Request.requested_at.desc()
        )
        members = group.my_members()

        total = requests.count()
        requests = requests.offset(offset).limit(limit)

        return self.render(request, 
            "group-requests.html", group=group, requests=requests,
            members=members, status=status, statuses=REQUEST_STATUS_CHOICES,
            offset=offset, limit=limit, total=total
        )


class AuditsComplete(GrouperView):
    def post(self, request, audit_id):
        user = self.current_user
        if not user.has_permission(PERMISSION_AUDITOR):
            raise PermissionDenied

        audit = self.session.query(Audit).filter(Audit.id == audit_id).one()

        # only owners can complete
        owner_ids = {member.id for member in audit.group.my_owners().values()}
        if user.id not in owner_ids:
            return self.forbidden()

        if audit.complete:
            return redirect("/groups/{}".format(audit.group.name))

        edges = {}
        for argument in request.POST:
            if argument.startswith('audit_'):
                edges[int(argument.split('_')[1])] = request.POST[argument][0]

        for member in audit.my_members():
            if member.id in edges:
                # You can only approve yourself (otherwise you can remove yourself
                # from the group and leave it ownerless)
                if member.member.id == user.id:
                    member.status = "approved"
                elif edges[member.id] in AUDIT_STATUS_CHOICES:
                    member.status = edges[member.id]

        self.session.commit()

        # Now if it's completable (no pendings) then mark it complete, else redirect them
        # to the group page.
        if not audit.completable:
            return redirect('/groups/{}'.format(audit.group.name))

        # Complete audits have to be "enacted" now. This means anybody marked as remove has to
        # be removed from the group now.
        for member in audit.my_members():
            if member.status == "remove":
                audit.group.revoke_member(self.current_user, member.member,
                                          "Revoked as part of audit.")
                AuditLog.log(self.session, self.current_user.id, 'remove_member',
                             'Removed membership in audit: {}'.format(member.member.name),
                             on_group_id=audit.group.id)

        audit.complete = True
        self.session.commit()

        # Now cancel pending emails
        self.cancel_async_emails('audit-{}'.format(audit.group.id))

        AuditLog.log(self.session, self.current_user.id, 'complete_audit',
                     'Completed group audit.', on_group_id=audit.group.id)

        return redirect('/groups/{}'.format(audit.group.name))


class AuditsCreate(GrouperView):
    def get(self, request):
        user = self.current_user
        if not user.has_permission(AUDIT_MANAGER):
            raise PermissionDenied

        return self.render(request, 
            "audit-create.html", form=AuditCreateForm(),
        )

    def post(self, request):
        form = AuditCreateForm(request.POST)
        if not form.validate():
            return self.render(request, 
                "audit-create.html", form=form,
                alerts=self.get_form_alerts(form.errors)
            )

        user = self.current_user
        if not user.has_permission(AUDIT_MANAGER):
            raise PermissionDenied

        # Step 1, detect if there are non-completed audits and fail if so.
        open_audits = self.session.query(Audit).filter(
            Audit.complete == False).all()
        if open_audits:
            raise Exception("Sorry, there are audits in progress.")
        ends_at = datetime.strptime(form.data["ends_at"], "%m/%d/%Y")

        # Step 2, find all audited groups and schedule audits for each.
        audited_groups = []
        for groupname in self.graph.groups:
            if not self.graph.get_group_details(groupname)["audited"]:
                continue
            group = Group.get(self.session, name=groupname)
            audit = Audit(
                group_id=group.id,
                ends_at=ends_at,
            )
            try:
                audit.add(self.session)
                self.session.flush()
            except IntegrityError:
                self.session.rollback()
                raise Exception("Failed to start the audit. Please try again.")

            # Update group with new audit
            audited_groups.append(group)
            group.audit_id = audit.id

            # Step 3, now get all members of this group and set up audit rows for those edges.
            for member in group.my_members().values():
                auditmember = AuditMember(
                    audit_id=audit.id, edge_id=member.edge_id
                )
                try:
                    auditmember.add(self.session)
                except IntegrityError:
                    self.session.rollback()
                    raise Exception("Failed to start the audit. Please try again.")

        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'start_audit',
                     'Started global audit.')

        # Calculate schedule of emails, basically we send emails at various periods in advance
        # of the end of the audit period.
        schedule_times = []
        not_before = datetime.utcnow() + timedelta(1)
        for days_prior in (28, 21, 14, 7, 3, 1):
            email_time = ends_at - timedelta(days_prior)
            email_time.replace(hour=17, minute=0, second=0)
            if email_time > not_before:
                schedule_times.append((days_prior, email_time))

        # Now send some emails. We do this separately/later to ensure that the audits are all
        # created. Email notifications are sent multiple times if group audits are still
        # outstanding.
        for group in audited_groups:
            mail_to = [
                member.name
                for member in group.my_users()
                if GROUP_EDGE_ROLES[member.role] in ('owner', 'np-owner')
            ]

            self.send_email(mail_to, 'Group Audit: {}'.format(group.name), 'audit_notice', {
                "group": group.name,
                "ends_at": ends_at,
            })

            for days_prior, email_time in schedule_times:
                self.send_async_email(
                    mail_to,
                    'Group Audit: {} - {} day(s) left'.format(group.name, days_prior),
                    'audit_notice_reminder',
                    {
                        "group": group.name,
                        "ends_at": ends_at,
                        "days_left": days_prior,
                    },
                    email_time,
                    async_key='audit-{}'.format(group.id),
                )

        return redirect("/audits")


class AuditsView(GrouperView):
    def get(self, request):
        user = self.current_user
        if not (user.has_permission(AUDIT_VIEWER) or user.has_permission(AUDIT_MANAGER)):
            raise PermissionDenied

        offset = int(request.GET.get("offset", 0))
        limit = int(request.GET.get("limit", 50))
        if limit > 200:
            limit = 200

        audits = (
            self.session.query(Audit)
            .order_by(Audit.started_at)
        )

        open_filter = request.GET.get("filter", "Open Audits")
        if open_filter == "Open Audits":
            audits = audits.filter(Audit.complete == False)

        open_audits = any([not audit.complete for audit in audits])
        total = audits.count()
        audits = audits.offset(offset).limit(limit).all()

        open_audits = self.session.query(Audit).filter(
            Audit.complete == False).all()
        can_start = user.has_permission(AUDIT_MANAGER)

        return self.render(request, 
            "audits.html", audits=audits, filter=open_filter, can_start=can_start,
            offset=offset, limit=limit, total=total, open_audits=open_audits,
        )


class GroupsView(GrouperView):
    def get(self, request):
        self.handle_refresh()
        offset = int(request.GET.get("offset", 0))
        limit = int(request.GET.get("limit", 100))
        enabled = bool(int(request.GET.get("enabled", 1)))
        audited_only = bool(int(request.GET.get("audited", 0)))
        if limit > 9000:
            limit = 9000

        if not enabled:
            groups = self.graph.get_disabled_groups()
            directly_audited_groups = None
        elif audited_only:
            groups = self.graph.get_groups(audited=True, directly_audited=False)
            directly_audited_groups = set([g.groupname for g in self.graph.get_groups(
                audited=True, directly_audited=True)])
        else:
            groups = self.graph.get_groups(audited=False)
            directly_audited_groups = set()
        total = len(groups)
        groups = groups[offset:offset + limit]

        form = GroupCreateForm()

        return self.render(request, 
            "groups.html", groups=groups, form=form,
            offset=offset, limit=limit, total=total, audited_groups=audited_only,
            directly_audited_groups=directly_audited_groups, enabled=enabled,
        )

    def post(self, request):
        form = GroupCreateForm(request.POST)
        if not form.validate():
            return self.render(request, 
                "group-create.html", form=form,
                alerts=self.get_form_alerts(form.errors)
            )

        user = self.current_user

        group = Group(
            groupname=form.data["groupname"],
            description=form.data["description"],
            canjoin=form.data["canjoin"]
        )
        try:
            group.add(self.session)
            self.session.flush()
        except IntegrityError:
            self.session.rollback()
            form.groupname.errors.append(
                "{} already exists".format(form.data["groupname"])
            )
            return self.render(request, 
                "group-create.html", form=form,
                alerts=self.get_form_alerts(form.errors)
            )

        group.add_member(user, user, "Group Creator", "actioned", None, form.data["creatorrole"])
        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'create_group',
                     'Created new group.', on_group_id=group.id)

        return redirect("/groups/{}?refresh=yes".format(group.name))


class GroupAdd(GrouperView):
    def get_form(self, request, role=None):
        """Helper to create a GroupAddForm populated with all users and groups as options.

        Note that the first choice is blank so the first user alphabetically
        isn't always selected.

        Returns:
            GroupAddForm object.
        """

        form = GroupAddForm(request.POST)

        form.role.choices = [["member", "Member"]]
        if role in ("owner", "np-owner"):
            form.role.choices.append(["manager", "Manager"])
            form.role.choices.append(["owner", "Owner"])
            form.role.choices.append(["np-owner", "No-Permissions Owner"])

        group_choices = [
            (group.groupname, "Group: " + group.groupname)  # (value, label)
            for group in get_all_groups(self.session)
        ]
        user_choices = [
            (user.username, "User: " + user.username)  # (value, label)
            for user in get_all_users(self.session)
        ]

        form.member.choices = [("", "")] + sorted(
            group_choices + user_choices,
            key=operator.itemgetter(1)
        )
        return form

    def get(self, request, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        if not self.current_user.can_manage(group):
            raise PermissionDenied

        members = group.my_members()
        my_role = self.current_user.my_role(members)
        return self.render(request, 
            "group-add.html", form=self.get_form(request, role=my_role), group=group
        )

    def post(self, request, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        if not self.current_user.can_manage(group):
            raise PermissionDenied

        members = group.my_members()
        my_role = self.current_user.my_role(members)
        form = self.get_form(request, role=my_role)
        if not form.validate():
            return self.render(request, 
                "group-add.html", form=form, group=group,
                alerts=self.get_form_alerts(form.errors)
            )

        member = get_user_or_group(self.session, form.data["member"])
        if not member:
            form.member.errors.append("User or group not found.")
        elif (member.type, member.name) in group.my_members():
            form.member.errors.append("User or group is already a member of this group.")
        elif group.name == member.name:
            form.member.errors.append("By definition, this group is a member of itself already.")

        # Ensure this doesn't violate auditing constraints
        fail_message = 'This join is denied with this role at this time.'
        try:
            user_can_join = assert_can_join(group, member, role=form.data["role"])
        except UserNotAuditor as e:
            user_can_join = False
            fail_message = e
        if not user_can_join:
            form.member.errors.append(fail_message)

        if form.member.errors:
            return self.render(request, 
                "group-add.html", form=form, group=group,
                alerts=self.get_form_alerts(form.errors)
            )

        expiration = None
        if form.data["expiration"]:
            expiration = datetime.strptime(form.data["expiration"], "%m/%d/%Y")

        group.add_member(
            requester=self.current_user,
            user_or_group=member,
            reason=form.data["reason"],
            status='actioned',
            expiration=expiration,
            role=form.data["role"]
        )
        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'join_group',
                     '{} added to group with role: {}'.format(
                         member.name, form.data["role"]),
                     on_group_id=group.id)

        return redirect("/groups/{}?refresh=yes".format(group.name))


class GroupRemove(GrouperView):
    def post(self, request, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        if not self.current_user.can_manage(group):
            raise PermissionDenied

        form = GroupRemoveForm(request.POST)
        if not form.validate():
            return self.send_error(status_code=400)

        member_type, member_name = form.data["member_type"], form.data["member"]

        members = group.my_members()
        if not members.get((member_type.capitalize(), member_name), None):
            return HttpResponse("404") # XXX(lfaraone)

        removed_member = get_user_or_group(self.session, member_name, user_or_group=member_type)

        if self.current_user == removed_member:
            return self.send_error(
                status_code=400,
                reason="Can't remove yourself. Leave group instead."
            )

        group.revoke_member(self.current_user, removed_member, "Removed by owner/np-owner/manager")
        AuditLog.log(self.session, self.current_user.id, 'remove_from_group',
                     '{} was removed from the group.'.format(removed_member.name),
                     on_group_id=group.id, on_user_id=removed_member.id)
        return redirect("/groups/{}?refresh=yes".format(group.name))


class GroupJoin(GrouperView):
    def get(self, request, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        group_md = self.graph.get_group_details(group.name)

        form = GroupJoinForm()
        form.member.choices = self._get_choices(group)
        return self.render(request, 
            "group-join.html", form=form, group=group, audited=group_md["audited"],
        )

    def post(self, request, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        form = GroupJoinForm(request.POST)
        form.member.choices = self._get_choices(group)
        if not form.validate():
            return self.render(request, 
                "group-join.html", form=form, group=group,
                alerts=self.get_form_alerts(form.errors)
            )

        member = self._get_member(form.data["member"])

        fail_message = 'This join is denied with this role at this time.'
        try:
            user_can_join = assert_can_join(group, member, role=form.data["role"])
        except UserNotAuditor as e:
            user_can_join = False
            fail_message = e
        if not user_can_join:
            return self.render(request, 
                "group-join.html", form=form, group=group,
                alerts=[
                    Alert('danger', fail_message, 'Audit Policy Enforcement')
                ]
            )

        if group.canjoin == "nobody":
            fail_message = 'This group cannot be joined at this time.'
            return self.render(request, 
                "group-join.html", form=form, group=group,
                alerts=[
                    Alert('danger', fail_message)
                ]
            )

        expiration = None
        if form.data["expiration"]:
            expiration = datetime.strptime(form.data["expiration"], "%m/%d/%Y")

        group.add_member(
            requester=self.current_user,
            user_or_group=member,
            reason=form.data["reason"],
            status=GROUP_JOIN_CHOICES[group.canjoin],
            expiration=expiration,
            role=form.data["role"]
        )
        self.session.commit()

        if group.canjoin == 'canask':
            AuditLog.log(self.session, self.current_user.id, 'join_group',
                         '{} requested to join with role: {}'.format(
                             member.name, form.data["role"]),
                         on_group_id=group.id)

            mail_to = [
                user.name
                for user in group.my_users()
                if GROUP_EDGE_ROLES[user.role] in ('manager', 'owner', 'np-owner')
            ]

            self.send_email(mail_to, 'Request to join: {}'.format(group.name), 'pending_request', {
                "requester": member.name,
                "requested_by": self.current_user.name,
                "requested": group.name,
                "reason": form.data["reason"],
                "expiration": expiration,
                "role": form.data["role"],
            })

        elif group.canjoin == 'canjoin':
            AuditLog.log(self.session, self.current_user.id, 'join_group',
                         '{} auto-approved to join with role: {}'.format(
                             member.name, form.data["role"]),
                         on_group_id=group.id)
        else:
            raise Exception('Need to update the GroupJoin.post audit logging')

        return redirect("/groups/{}?refresh=yes".format(group.name))

    def _get_member(self, member_choice):
        member_type, member_name = member_choice.split(": ", 1)
        resource = None

        if member_type == "User":
            resource = User
        elif member_type == "Group":
            resource = Group

        if resource is None:
            return

        return self.session.query(resource).filter_by(
            name=member_name, enabled=True
        ).one()

    def _get_choices(self, group):
        choices = []

        members = group.my_members()

        if ("User", self.current_user.name) not in members:
            choices.append(
                ("User: {}".format(self.current_user.name), ) * 2
            )

        for _group in self.current_user.my_groups():
            if group.name == _group.name:  # Don't add self.
                continue
            if _group.role < 1:  # manager, owner, and np-owner only.
                continue
            if ("Group", _group.name) in members:
                continue

            choices.append(
                ("Group: {}".format(_group.name), ) * 2
            )

        return choices


class GroupLeave(GrouperView):
    def get(self, request, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        members = group.my_members()
        if not self.current_user.my_role(members):
            raise PermissionDenied

        return self.render(request, 
            "group-leave.html", group=group
        )

    def post(self, request, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        members = group.my_members()
        if not self.current_user.my_role(members):
            raise PermissionDenied

        group.revoke_member(self.current_user, self.current_user, "User self-revoked.")

        AuditLog.log(self.session, self.current_user.id, 'leave_group',
                     '{} left the group.'.format(self.current_user.name),
                     on_group_id=group.id)

        return redirect("/groups/{}?refresh=yes".format(group.name))


class GroupEdit(GrouperView):
    def get(self, request, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        if not self.current_user.can_manage(group):
            raise PermissionDenied

        form = GroupEditForm(obj=group)

        return self.render(request, "group-edit.html", group=group, form=form)

    def post(self, request, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        if not self.current_user.can_manage(group):
            raise PermissionDenied

        form = GroupEditForm(request.POST, obj=group)
        if not form.validate():
            return self.render(request, 
                "group-edit.html", group=group, form=form,
                alerts=self.get_form_alerts(form.errors)
            )

        group.groupname = form.data["groupname"]
        group.description = form.data["description"]
        group.canjoin = form.data["canjoin"]
        Counter.incr(self.session, "updates")

        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            form.groupname.errors.append(
                "{} already exists".format(form.data["groupname"])
            )
            return self.render(request, 
                "group-edit.html", group=group, form=form,
                alerts=self.get_form_alerts(form.errors)
            )

        AuditLog.log(self.session, self.current_user.id, 'edit_group',
                     'Edited group.', on_group_id=group.id)

        return redirect("/groups/{}".format(group.name))


class GroupEnable(GrouperView):
    def post(self, request, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        members = group.my_members()
        if not self.current_user.my_role(members) in ("owner", "np-owner"):
            raise PermissionDenied

        group.enable()
        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'enable_group',
                     'Enabled group.', on_group_id=group.id)

        return redirect("/groups/{}?refresh=yes".format(group.name))


class GroupDisable(GrouperView):
    def post(self, request, group_id=None, name=None):
        group = Group.get(self.session, group_id, name)
        if not group:
            return HttpResponse("404") # XXX(lfaraone)

        members = group.my_members()
        if not self.current_user.my_role(members) in ("owner", "np-owner"):
            raise PermissionDenied

        group.disable()
        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'disable_group',
                     'Disabled group.', on_group_id=group.id)

        return redirect("/groups/{}?refresh=yes".format(group.name))


class PublicKeyAdd(GrouperView):
    def get(self, request, user_id=None, name=None):
        user = User.get(self.session, user_id, name)
        if not user:
            return HttpResponse("404") # XXX(lfaraone)

        if (user.name != self.current_user.name) and not self.current_user.user_admin:
            raise PermissionDenied

        return self.render(request, "public-key-add.html", form=PublicKeyForm(), user=user)

    def post(self, request, user_id=None, name=None):
        user = User.get(self.session, user_id, name)
        if not user:
            return HttpResponse("404") # XXX(lfaraone)

        if (user.name != self.current_user.name) and not self.current_user.user_admin:
            raise PermissionDenied

        form = PublicKeyForm(request.POST)
        if not form.validate():
            return self.render(request, 
                "public-key-add.html", form=form, user=user,
                alerts=self.get_form_alerts(form.errors),
            )

        pubkey = sshpubkey.PublicKey.from_str(form.data["public_key"])
        db_pubkey = PublicKey(
            user=user,
            public_key='%s %s %s' % (pubkey.key_type, pubkey.key, pubkey.comment),
            fingerprint=pubkey.fingerprint,
            key_size=pubkey.key_size,
            key_type=pubkey.key_type,
        )
        try:
            db_pubkey.add(self.session)
            self.session.flush()
        except IntegrityError:
            self.session.rollback()
            form.public_key.errors.append(
                "Key already in use. Public keys must be unique."
            )
            return self.render(request, 
                "public-key-add.html", form=form, user=user,
                alerts=self.get_form_alerts(form.errors),
            )

        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'add_public_key',
                     'Added public key: {}'.format(pubkey.fingerprint),
                     on_user_id=user.id)

        self.send_email([user.name], 'Public SSH key added', 'ssh_keys_changed', {
            "actioner": self.current_user.name,
            "changed_user": user.name,
            "action": "added",
        })

        return redirect("/users/{}?refresh=yes".format(user.name))


class PublicKeyDelete(GrouperView):
    def get(self, request, user_id=None, name=None, key_id=None):
        user = User.get(self.session, user_id, name)
        if not user:
            return HttpResponse("404") # XXX(lfaraone)

        if (user.name != self.current_user.name) and not self.current_user.user_admin:
            raise PermissionDenied

        key = self.session.query(PublicKey).filter_by(id=key_id, user_id=user.id).scalar()
        if not key:
            return HttpResponse("404") # XXX(lfaraone)

        return self.render(request, "public-key-delete.html", user=user, key=key)

    def post(self, request, user_id=None, name=None, key_id=None):
        user = User.get(self.session, user_id, name)
        if not user:
            return HttpResponse("404") # XXX(lfaraone)

        if (user.name != self.current_user.name) and not self.current_user.user_admin:
            raise PermissionDenied

        key = self.session.query(PublicKey).filter_by(id=key_id, user_id=user.id).scalar()
        if not key:
            return HttpResponse("404") # XXX(lfaraone)

        key.delete(self.session)
        self.session.commit()

        AuditLog.log(self.session, self.current_user.id, 'delete_public_key',
                     'Deleted public key: {}'.format(key.fingerprint),
                     on_user_id=user.id)

        self.send_email([user.name], 'Public SSH key removed', 'ssh_keys_changed', {
            "actioner": self.current_user.name,
            "changed_user": user.name,
            "action": "removed",
        })

        return redirect("/users/{}?refresh=yes".format(user.name))


class Help(GrouperView):
    def get(self, request):
        permissions = (
            self.session.query(Permission)
            .order_by(Permission.name)
        )
        d = {permission.name: permission for permission in permissions}

        return self.render(request, "help.html",
                    how_to_get_help=settings.how_to_get_help,
                    site_docs=settings.site_docs,
                    grant_perm=d[PERMISSION_GRANT],
                    create_perm=d[PERMISSION_CREATE],
                    audit_perm=d[PERMISSION_AUDITOR])


# Don't use GraphHandler here as we don't want to count
# these as requests.
class Stats(RequestHandler):
    def get(self, request):
        return self.write(stats.to_dict())


class NotFound(GrouperView):
    def get(self, request):
        return HttpResponse("404") # XXX(lfaraone)
