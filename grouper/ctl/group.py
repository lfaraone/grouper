import logging

from grouper.ctl.util import ensure_valid_username, ensure_valid_groupname, make_session
from grouper.models import AuditLog, Group, User


@ensure_valid_username
@ensure_valid_groupname
def mod_members(args):
    session = make_session()
    group = session.query(Group).filter_by(groupname=args.groupname).scalar()
    if not group:
        logging.error("No such group %s".format(args.groupname))
        return

    for username in args.username:
        user = User.get(session, name=username)
        if not user:
            logging.error("no such user '{}'".format(username))
            return

        if args.subcommand == "add_member":
            logging.info("Adding {} to group {}".format(username, args.groupname))
            group.add_member(user, user, "grouper-ctl join", status="actioned")
            AuditLog.log(
                session, user.id, 'join_group',
                '{} manually joined via grouper-ctl'.format(username),
                on_group_id=group.id)
            session.commit()

        elif args.subcommand == "remove_member":
            logging.info("Removing {} from group {}".format(username, args.groupname))
            group.revoke_member(user, user, "grouper-ctl remove")
            AuditLog.log(
                session, user.id, 'leave_group',
                '{} manually left via grouper-ctl'.format(username),
                on_group_id=group.id)
            session.commit()


def add_parser(subparsers):
    group_parser = subparsers.add_parser(
        "group", help="Edit groups and membership")
    #group_parser.set_defaults(func=group_command)
    group_subparser = group_parser.add_subparsers(dest="subcommand")

    group_join_parser = group_subparser.add_parser(
        "add_member", help="Join one or more users to a group")
    group_join_parser.set_defaults(func=mod_members)
    group_join_parser.add_argument("groupname")
    group_join_parser.add_argument("username", nargs="+")

    group_remove_parser = group_subparser.add_parser(
        "remove_member", help="Remove one or more users from a group")
    group_remove_parser.set_defaults(func=mod_members)
    group_remove_parser.add_argument("groupname")
    group_remove_parser.add_argument("username", nargs="+")
