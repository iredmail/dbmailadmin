# Author: Zhang Huangbin <zhb@iredmail.org>

from libs.iredutils import reEmail, reDomain

urls = [
    # Make url ending with or without '/' going to the same class.
    '/(.*)/',                           'controllers.base.redirect',

    # used to display jpegPhoto.
    '/img/(.*)',                        'controllers.base.img',

    '/',                                'controllers.dbmail_mysql.basic.Login',
    '/login',                           'controllers.dbmail_mysql.basic.Login',
    '/logout',                          'controllers.dbmail_mysql.basic.Logout',
    '/dashboard',                       'controllers.dbmail_mysql.basic.Dashboard',
    '/dashboard/(checknew)',            'controllers.dbmail_mysql.basic.Dashboard',

    # Search.
    '/search',                          'controllers.dbmail_mysql.basic.Search',

    # Perform some operations from search page.
    '/action/(user|alias)',   'controllers.dbmail_mysql.basic.OperationsFromSearchPage',

    # Domain related.
    '/domains',                         'controllers.dbmail_mysql.domain.List',
    '/domains/page/(\d+)',              'controllers.dbmail_mysql.domain.List',
    '/profile/domain/(general|aliases|relay|bcc|catchall|throttle|advanced)/(%s$)' % reDomain,  'controllers.dbmail_mysql.domain.Profile',
    '/profile/domain/(%s)' % reDomain,  'controllers.dbmail_mysql.domain.Profile',
    '/create/domain',                   'controllers.dbmail_mysql.domain.Create',

    # Admin related.
    '/admins',                          'controllers.dbmail_mysql.admin.List',
    '/admins/page/(\d+)',               'controllers.dbmail_mysql.admin.List',
    '/profile/admin/(general|password)/(%s$)' % reEmail,     'controllers.dbmail_mysql.admin.Profile',
    '/create/admin',                    'controllers.dbmail_mysql.admin.Create',

    # User related.
    # /domain.ltd/users
    '/users',                           'controllers.dbmail_mysql.user.List',
    '/users/(%s$)' % reDomain,           'controllers.dbmail_mysql.user.List',
    '/users/(%s)/page/(\d+)' % reDomain, 'controllers.dbmail_mysql.user.List',
    # Create user.
    '/create/user/(%s$)' % reDomain,     'controllers.dbmail_mysql.user.Create',
    '/create/user',                     'controllers.dbmail_mysql.user.Create',
    # Profile pages.
    '/profile/user/(general|forwarding|aliases|bcc|relay|wblist|password|throttle|advanced)/(%s$)' % reEmail,      'controllers.dbmail_mysql.user.Profile',

    # Import accouts.
    '/import/user',                     'controllers.dbmail_mysql.user.ImportUser',

    # Alias related.
    '/aliases',                         'controllers.dbmail_mysql.alias.List',
    '/aliases/(%s$)' % reDomain,                         'controllers.dbmail_mysql.alias.List',
    '/aliases/(%s)/page/(\d+)' % reDomain,              'controllers.dbmail_mysql.alias.List',
    '/profile/alias/(general|members)/(%s$)' % reEmail,  'controllers.dbmail_mysql.alias.Profile',
    '/create/alias/(%s$)' % reDomain,                    'controllers.dbmail_mysql.alias.Create',
    '/create/alias',                                    'controllers.dbmail_mysql.alias.Create',
]
