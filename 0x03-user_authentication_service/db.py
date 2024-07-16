#!/usr/bin/env python3
"""
The DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.ext.declarative import declarative_base

from user import Base, User


class DB:
    """DB class definition
    """

    def __init__(self) -> None:
        """Initializing a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db",
                                     echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        A User object is created and saved to the database
        Args:
            email (str): user's email address
            hashed_password (str): password hashed by bcrypt's hashpw
        Return:
            Latest User object
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """
        A user who has an attribute matching the attributes passed
        as arguments is returned.
        Args:
            attributes (dict): dictionary of attributes matching the user
        Return:
            matching user or error
        """
        all_users = self._session.query(User)
        for k, v in kwargs.items():
            if k not in User.__dict__:
                raise InvalidRequestError
            for usr in all_users:
                if getattr(usr, k) == v:
                    return usr
        raise NoResultFound

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        A user's attributes are updated
        Args:
            user_id (int): user's id
            kwargs (dict): dict of key, value pairs that represent the
                           attributes and the corresponding values to
                           be updated.
        Return:
            Null
        """
        try:
            usr = self.find_user_by(id=user_id)
        except NoResultFound:
            raise ValueError()
        for k, v in kwargs.items():
            if hasattr(usr, k):
                setattr(usr, k, v)
            else:
                raise ValueError
        self._session.commit()
