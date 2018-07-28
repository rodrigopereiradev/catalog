import sys
from sqlalchemy import Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class Restaurant(Base):
    __tablename__ = 'restaurant'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name
        }


class MenuItem(Base):
    __tablename__ = "menu_item"
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(250))
    price = Column(String(8))
    course = Column(String(250))
    restaurant_id = Column(Integer, ForeignKey('restaurant.id'))
    restaurant = relationship(Restaurant)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'course': self.course
        }


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    email = Column(String(50), nullable=False)
    picture = Column(String)

    @property
    def serialize(self):
        return {
            'is': self.id,
            'name': self.name,
            'email': self.email,
            'picture': self.picture
        }


engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.create_all(engine)
