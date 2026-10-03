# app/services/error_handling.py
"""Shared error-handling decorator for blueprint routes."""
from functools import wraps

from flask import current_app, jsonify, render_template, request
from werkzeug.exceptions import HTTPException


def wants_json():
    """API callers and fetch()/XHR get JSON; page navigations get HTML."""
    if request.path.startswith('/api/') or request.method != 'GET' or request.is_json:
        return True
    best = request.accept_mimetypes.best_match(['application/json', 'text/html'])
    return best == 'application/json'


def error_handler(f):
    """Log unexpected exceptions and return a 500.

    HTTP errors raised inside the route (400 bad JSON, 404, 413, 415...)
    keep their own status. The response carries the exception type, not
    its message — messages often hold absolute paths and OS details;
    the full traceback is in the log (and in the response in debug mode).
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except HTTPException:
            raise
        except Exception as e:
            current_app.logger.error(f"Error in {f.__name__}: {e}", exc_info=True)
            if current_app.debug:
                message = f'{type(e).__name__}: {e}'
            else:
                message = f'Internal error ({type(e).__name__}); see the LitterBox log for details'
            if wants_json():
                return jsonify({'error': message}), 500
            return render_template('error.html', error=message), 500
    return decorated_function
