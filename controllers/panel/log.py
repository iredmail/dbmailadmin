# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from controllers import decorators
from libs.panel import LOG_EVENTS, log as loglib

cfg = web.iredconfig
session = web.config.get('_session')

if cfg.general.backend == 'ldap':
    from libs.ldaplib import admin as adminlib, connUtils
elif cfg.general.backend == 'mysql':
    from libs.mysql import admin as adminlib, connUtils
elif cfg.general.backend == 'dbmail_mysql':
    from libs.dbmail_mysql import admin as adminlib, connUtils


class Log:
    @decorators.require_login
    def GET(self):
        i = web.input(_unicode=False,)

        # Get queries.
        self.event = web.safestr(i.get('event', 'all'))
        self.domain = web.safestr(i.get('domain', 'all'))
        self.admin = web.safestr(i.get('admin', 'all'))
        self.cur_page = web.safestr(i.get('page', '1'))

        if not self.cur_page.isdigit() or self.cur_page == '0':
            self.cur_page = 1
        else:
            self.cur_page = int(self.cur_page)

        logLib = loglib.Log()
        total, entries = logLib.listLogs(
                event=self.event,
                domain=self.domain,
                admin=self.admin,
                cur_page=self.cur_page,
                )

        # Pre-defined
        allDomains = []
        allAdmins = []

        if cfg.general.backend == 'ldap':
            # Get all managed domains under control.
            connutils = connUtils.Utils()
            qr = connutils.getManagedDomains(mail=session.get('username'), attrs=['domainName'],)
            if qr[0] is True:
                allDomains = [str(v[1]['domainName'][0]).lower() for v in qr[1]]

            # Get all admins.
            if session.get('domainGlobalAdmin') is True:
                adminLib = adminlib.Admin()
                result = adminLib.listAccounts(attrs=['mail'])
                if result[0] is not False:
                    allAdmins = [v[1]['mail'][0] for v in result[1]]
            else:
                allAdmins = [self.admin]

        elif cfg.general.backend in ['mysql', 'dbmail_mysql', ]:
            # Get all managed domains under control.
            connutils = connUtils.Utils()
            qr = connutils.getManagedDomains(admin=session.get('username'), domainNameOnly=True,)
            if qr[0] is True:
                allDomains = qr[1]

            # Get all admins.
            if session.get('domainGlobalAdmin') is True:
                adminLib = adminlib.Admin()
                qr = adminLib.getAllAdmins(columns=['username'])
                if qr[0] is True:
                    for r in qr[1]:
                        allAdmins += [r.username]
            else:
                allAdmins = [self.admin]

        return web.render(
            'panel/log.html',
            event=self.event,
            domain=self.domain,
            admin=self.admin,
            allEvents=LOG_EVENTS,
            cur_page=self.cur_page,
            total=total,
            entries=entries,
            allDomains=allDomains,
            allAdmins=allAdmins,
            msg=i.get('msg'),
        )

    @decorators.require_global_admin
    @decorators.csrf_protected
    @decorators.require_login
    def POST(self):
        i = web.input(_unicode=False, id=[],)
        action = web.safestr(i.get('action', 'delete'))

        deleteAll = False
        if action == 'deleteAll':
            deleteAll = True

        logLib = loglib.Log()
        result = logLib.delete(data=i, deleteAll=deleteAll,)

        if result[0] is True:
            raise web.seeother('/system/log?msg=DELETED')
        else:
            raise web.seeother('/system/log?msg=%s' % web.urlquote(result[1]))
