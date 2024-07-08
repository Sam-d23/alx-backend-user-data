#!/usr/bin/env python3
"""Imports route definitions from the 'index' and
'users' modules within the 'api.v1.views' package.
"""
from flask import Blueprint

app_views = Blueprint("app_views", __name__, url_prefix="/api/v1")

from api.v1.views.index import *
from api.v1.views.users import *

User.load_from_file()
