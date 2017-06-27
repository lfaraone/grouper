from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import relationship

from grouper.models.base.model_base import Model



class GroupMetadata(Model):

    __tablename__ = "group_metadata"
    __table_args__ = (
        UniqueConstraint('group_id', 'data_key', name='gidx1'),
    )

    id = Column(Integer, primary_key=True)

    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    group = relationship("Group", foreign_keys=[group_id])

    data_key = Column(String(length=64), nullable=False)
    data_value = Column(String(length=64), nullable=False)
    last_modified = Column(DateTime, default=datetime.utcnow, nullable=False)