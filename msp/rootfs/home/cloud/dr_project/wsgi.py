"""Production WSGI entry point for the ChatOps service.

Gunicorn imports this module from the operational ChatOps directory.  The
background workers are intentionally started here because ``app.py`` is now
an application-factory wrapper and is no longer a Flask development-server
entry point.
"""

from app import app
from chatops_core import start_cleanup_worker, start_expiry_worker


start_expiry_worker(app)
start_cleanup_worker(app)
