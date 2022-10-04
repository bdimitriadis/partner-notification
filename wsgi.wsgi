#!/usr/bin/python3
import sys
import logging



logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, "/var/www/partner_notification")
from app import app as application

# application.secret_key = 'Thisissupposedtobesecret!'

# if path not in sys.path:
#     sys.path.insert(0, path)
