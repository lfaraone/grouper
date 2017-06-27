import re

from datetime import datetime

from grouper.constants import PERMISSION_VALIDATION
from grouper.model_soup import Group, User
from grouper.models.group_metadata import GroupMetadata
from grouper.models.base.session import Session


class GroupMetadataType(object):
    key_name = None
    human_readable_name = None

    def can_set(self, group, user):
        # type: (Group, User) -> bool
        return user in group.my_members()

    def get(self, session, group):
        # type: (Session, Group) -> GroupMetadata
        return session.query(GroupMetadata).filter(
            GroupMetadata.group_id == group.id,
            GroupMetadata.data_key == self.key_name
        ).scalar()

    def set(self, session, group, value):
        # type: (Session, Group) -> None
        group_md = self.get(session, group)
        if group_md is None:
            group_md = GroupMetadata()
            group_md.group_id = group.id
            group_md.data_key = self.key_name
        group_md.data_value = value
        group_md.last_modified = datetime.now()
        group_md.add(session)
        session.commit()

class _GroupEmailMetadata(GroupMetadataType):
    key_name = "email"
    human_readable_name = "Email address"

GroupEmailMetadata = _GroupEmailMetadata()

def get_user_metadata_by_key(session, user_id, data_key):
    """Return the user's metadata if it has the matching key

    Args:
        session(models.base.session.Session): database session
        user_id(int): id of user in question

    Returns:
        List of UserMetadata objects
    """
    pass


def set_user_metadata(session, user_id, data_key, data_value):
    """Set a single piece of user metadata.

    Args:
        session(models.base.session.Session): database session
        user_id(int): id of user in question
        data_key(str): the metadata key (limited to 64 character by db schema)
        data_value(str):  the metadata value (limited to 64 character by db
                schema) if this is None, the metadata entry is deleted.

    Returns:
        the UserMetadata object or None if entry was deleted
    """
    pass
