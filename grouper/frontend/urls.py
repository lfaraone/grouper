from . import views
from ..constants import NAME_VALIDATION, NAME2_VALIDATION, PERMISSION_VALIDATION
from django.conf.urls import url

urlpatterns = [
    url(r"audits$", views.AuditsView.as_view()),
    url(r"audits/(?P<audit_id>[0-9]+)/complete$", views.AuditsComplete.as_view()),
    url(r"audits/create$", views.AuditsCreate.as_view()),
    url(r"groups$", views.GroupsView.as_view()),
    url(r"permissions/create$", views.PermissionsCreate.as_view()),
    url(r"permissions/{}$".format(PERMISSION_VALIDATION), views.PermissionView.as_view()),
    url(r"permissions$", views.PermissionsView.as_view()),
    url(
        r"permissions/{}/enable-auditing$".format(PERMISSION_VALIDATION),
        views.PermissionEnableAuditing.as_view()
    ),
    url(
        r"permissions/{}/disable-auditing$".format(PERMISSION_VALIDATION),
        views.PermissionDisableAuditing.as_view()
    ),
    url(r"permissions/grant/{}$".format(NAME_VALIDATION), views.PermissionsGrant.as_view()),
    url(
        r"permissions/{}/revoke/(?P<mapping_id>[0-9]+)$".format(PERMISSION_VALIDATION),
        views.PermissionsRevoke.as_view()
    ),
    url(r"search", views.Search.as_view()),
    url(r"users$", views.UsersView.as_view()),
    url(r"users/public-keys", views.UsersPublicKey.as_view()),
    url(r"user/requests", views.UserRequests.as_view()),
]

for regex in (r"(?P<user_id>[0-9]+)", NAME_VALIDATION):
    urlpatterns.extend([
        url(r"users/{}".format(regex), views.UserView.as_view()),
        url(r"users/{}/disable".format(regex), views.UserDisable.as_view()),
        url(r"users/{}/enable".format(regex), views.UserEnable.as_view()),
        url(r"users/{}/public-key/add".format(regex), views.PublicKeyAdd.as_view()),
        url(
            r"users/{}/public-key/(?P<key_id>[0-9]+)/delete".format(regex),
            views.PublicKeyDelete.as_view()
        ),
    ])

for regex in (r"(?P<group_id>[0-9]+)", NAME_VALIDATION):
    urlpatterns.extend([
        url(r"groups/{}$".format(regex), views.GroupView.as_view()),
        url(r"groups/{}/edit$".format(regex), views.GroupEdit.as_view()),
        url(r"groups/{}/disable$".format(regex), views.GroupDisable.as_view()),
        url(r"groups/{}/enable$".format(regex), views.GroupEnable.as_view()),
        url(r"groups/{}/join$".format(regex), views.GroupJoin.as_view()),
        url(r"groups/{}/add$".format(regex), views.GroupAdd.as_view()),
        url(r"groups/{}/remove$".format(regex), views.GroupRemove.as_view()),
        url(r"groups/{}/leave$".format(regex), views.GroupLeave.as_view()),
        url(r"groups/{}/requests$".format(regex), views.GroupRequests.as_view()),
        url(
            r"groups/{}/requests/(?P<request_id>[0-9]+)$".format(regex),
            views.GroupRequestUpdate.as_view()
        ),
        url(
            r"groups/{}/edit/(?P<member_type>user|group)/{}$".format(regex, NAME2_VALIDATION),
            views.GroupEditMember.as_view()
        ),
    ])

urlpatterns += [
    url(r"help", views.Help.as_view()),
    #    url(r"debug/stats", views.Stats.as_view()),

    url(r"$", views.Index.as_view()),
]
