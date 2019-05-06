import os
import sysconfig
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.orm import backref
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    """
    Registered user information is stored in db
    """
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))
    provider = Column(String(250))

    @property
    def serialize(self):
        return{
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'picture': self.picture,
            'provider': self.provider
        }

class Categories(Base):
    """
    Registered categories is stored in db
    """
    __tablename__ = 'categories'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable = False)
    img = Column(String(250), nullable = True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'name': self.name,
            'id': self.id,
            'img': self.img,
        }

class CategoryItem(Base):
    """
    Registered items in each category is stored in db
    """
    __tablename__ = 'category_item'

    name = Column(String(250), nullable = False)
    id = Column(Integer, primary_key = True)
    description = Column(String(500))
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    category_id = Column(Integer, ForeignKey('categories.id', ondelete='CASCADE'))
    user_id = Column(Integer, ForeignKey('user.id'))
    category = relationship(Categories, backref= backref('category_item', cascade='delete'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'name': self.name,
            'id': self.id,
            'description': self.description,
            'time_created': self.time_created,
            'category_id': self.category_id,
            'user_id': self.user_id,

        }

engine = create_engine('sqlite:///itemcatalog.db')
#Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)