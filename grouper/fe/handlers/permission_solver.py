from grouper.fe.util import GrouperHandler
from grouper.models.group import Group
from grouper.models.permission import Permission
from grouper.permissions import get_groups_by_permission 
from grouper.util import matches_glob

class PermissionSolver(GrouperHandler):
    def get(self):
        permission = None
        mapped_groups = []

        name = self.get_argument("perm", None)
        if name is not None:
            permission = Permission.get(self.session, name)
            if not permission:
                return self.notfound()
            mapped_groups = get_groups_by_permission(self.session, permission, Group.description, Group.canjoin)

        argument = self.get_argument("arg", None)

        if argument is not None:
            p1 = set(g for g in mapped_groups if g[1] == argument)
            p2 = set(g for g in mapped_groups if matches_glob(g[1], argument))
            p3 = set(g for g in mapped_groups if g[1] == '*')
            mapped_groups = []
            mapped_groups.extend(p1)
            mapped_groups.extend(p2 - p3 - p1)
            mapped_groups.extend(p3)

        self.render(
            "permission_solver.html", permission=permission, argument=argument,
            direct_groups=p1,
            glob_groups=list(p2 - p1 - p3) + list(p3),
            mapped_groups=mapped_groups
        )
