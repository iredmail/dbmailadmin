# Author: Zhang Huangbin <zhb@iredmail.org>

import web

session = web.config.get('_session')

class redirect:
    """Make url ending with or without '/' going to the same class."""
    def GET(self, path):
        raise web.seeother('/' + str(path))

class img:
    def GET(self, encoded_img):
        web.header('Content-Type', 'image/jpeg')
        return encoded_img.decode('base64')


#
# Decorators
#
def require_login(func):
    def proxyfunc(self, *args, **kw):
        if session.get('logged') is True:
            return func(self, *args, **kw)
        else:
            session.kill()
            raise web.seeother('/login?msg=loginRequired')
    return proxyfunc

def require_global_admin(func):
    def proxyfunc(self, *args, **kw):
        if session.get('domainGlobalAdmin') is True:
            return func(self, *args, **kw)
        else:
            raise web.seeother('/domains?msg=PERMISSION_DENIED')
    return proxyfunc


def csrf_protected(f):
    def decorated(*args, **kw):
        inp = web.input()
        if not (inp.has_key('csrf_token') and inp.csrf_token == session.pop('csrf_token', None)):
            return web.render('error_csrf.html')
        return f(*args, **kw)
    return decorated
