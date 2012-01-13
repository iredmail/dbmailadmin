# encoding: utf-8

# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from libs import iredutils, settings
from libs.dbmail_mysql import core, decorators, connUtils

cfg = web.iredconfig
session = web.config.get('_session')


class Admin(core.MySQLWrap):
    def __del__(self):
        pass

    def getAllAdmins(self, columns=[]):
        """Get all admins. Return (True, [records])."""
        try:
            if columns:
                result = self.conn.select('dbmail_admins', what=','.join(columns),)
            else:
                result = self.conn.select('dbmail_admins')

            return (True, list(result))
        except Exception, e:
            return (False, str(e))

    @decorators.require_global_admin
    def listAccounts(self, cur_page=1,):
        '''List all admins.'''
        # Pre-defined.
        self.total = 0

        # Get current page.
        cur_page = int(cur_page)

        self.sql_limit = ''
        if cur_page > 0:
            self.sql_limit = 'LIMIT %d OFFSET %d' % (
                settings.PAGE_SIZE_LIMIT,
                (cur_page-1)*settings.PAGE_SIZE_LIMIT,
            )

        try:
            result = self.conn.select('dbmail_admins', what='COUNT(username) AS total')
            if len(result) > 0:
                self.total = result[0].total or 0
        except Exception, e:
            pass

        try:
            result = self.conn.query(
                """
                SELECT name, username, language, created, active
                FROM dbmail_admins
                ORDER BY username ASC
                %s
                """ % (self.sql_limit)
            )
            return (True, self.total, list(result))
        except Exception, e:
            return (False, str(e))


    # Get number of domains under control.
    def getNumberOfManagedAccounts(self, admin=None, accountType='domain', domains=[],):
        if admin is None:
            self.admin = session.get('username')
        else:
            self.admin = str(admin)

        if not iredutils.isEmail(self.admin):
            return 0

        self.domains = []
        if accountType in ['user', 'alias',]:
            if len(domains) > 0:
                self.domains = [str(d).lower() for d in domains if iredutils.isDomain(d)]
            else:
                connutils = connUtils.Utils()
                qr = connutils.getManagedDomains(admin=self.admin, domainNameOnly=True)
                if qr[0] is True:
                    self.domains = qr[1]

        if accountType == 'domain':
            try:
                if self.isGlobalAdmin(self.admin):
                    result = self.conn.select('dbmail_domains', what='COUNT(domain) AS total',)
                else:
                    result = self.conn.query(
                        """
                        SELECT COUNT(dbmail_domains.domain) AS total
                        FROM dbmail_domains
                        LEFT JOIN dbmail_domain_admins ON (dbmail_domains.domain=dbmail_domain_admins.domain)
                        WHERE dbmail_domain_admins.username=%s
                        """ % (web.sqlquote(self.admin))
                    )

                total = result[0].total or 0
                return total
            except:
                pass
        elif accountType == 'user':
            try:
                if self.isGlobalAdmin(self.admin):
                    if len(self.domains) >= 0:
                        result = self.conn.select('dbmail_users',
                                                  what='COUNT(user_idnr) AS total',
                                                  where='domain IN %s AND user_idnr > 3' % web.sqlquote(self.domains),
                                                 )
                    else:
                        result = self.conn.select('dbmail_users', what='COUNT(user_idnr) AS total', where='user_idnr>3')
                else:
                    self.sql_append_where = ''
                    if len(self.domains) > 0:
                        self.sql_append_where = 'AND dbmail_users.domain IN %s' % web.sqlquote(self.domains)

                    result = self.conn.query(
                        """
                        SELECT COUNT(dbmail_users.user_idnr) AS total
                        FROM dbmail_users
                        LEFT JOIN dbmail_domain_admins ON (dbmail_users.domain = dbmail_domain_admins.domain)
                        WHERE dbmail_domain_admins.username = %s %s
                        """ % (web.sqlquote(self.admin), self.sql_append_where,)
                    )

                total = result[0].total or 0
                return total
            except:
                pass
        elif accountType == 'alias':
            try:
                if self.isGlobalAdmin(self.admin):
                    if len(self.domains) == 0:
                        result = self.conn.select(
                            'dbmail_aliases',
                            what='COUNT(alias_idnr) AS total',
                        )
                    else:
                        result = self.conn.select(
                            'dbmail_aliases',
                            what='COUNT(alias_idnr) AS total',
                            where='domain IN %s' % web.sqlquote(self.domains),
                        )
                else:
                    self.sql_append_where = ''
                    if len(self.domains) == 0:
                        self.sql_append_where = 'AND dbmail_aliases.domain IN %s' % web.sqlquote(self.domains)

                    result = self.conn.query(
                        """
                        SELECT COUNT(dbmail_aliases.alias_idnr) AS total
                        FROM dbmail_aliases
                        LEFT JOIN dbmail_domain_admins ON (dbmail_aliases.domain = dbmail_domain_admins.domain)
                        WHERE dbmail_domain_admins.username = %s %s
                        """ % (web.sqlquote(self.admin), self.sql_append_where,)
                    )

                total = result[0].total or 0
                return total
            except:
                pass

        return 0

    @decorators.require_global_admin
    def delete(self, mails=[]):
        if not isinstance(mails, list):
            return (False, 'INVALID_MAIL')

        self.mails = [str(v).lower() for v in mails if iredutils.isEmail(v)]
        self.sqlMails = web.sqlquote(self.mails)

        # Delete domain and related records.
        try:
            self.conn.delete('dbmail_admins', where='username IN %s' % self.sqlMails)
            self.conn.delete('domain_domain_admins', where='username IN %s' % self.sqlMails)

            web.logger(msg="Delete admin: %s." % ', '.join(self.mails), event='delete',)
            return (True,)
        except Exception, e:
            return (False, str(e))

    @decorators.require_global_admin
    def enableOrDisableAccount(self, accounts, active=True):
        return self.setAccountStatus(accounts=accounts, active=active, accountType='admin',)

    def profile(self, mail):
        self.mail = web.safestr(mail)
        self.domainGlobalAdmin = False

        if not iredutils.isEmail(self.mail):
            return (False, 'INVALID_MAIL')

        self.sqladmin = web.sqlquote(self.mail)
        try:
            result = self.conn.select('dbmail_admins', where='username=%s' % self.sqladmin, limit=1,)
            if len(result) == 1:
                if self.isGlobalAdmin(admin=self.mail):
                    self.domainGlobalAdmin = True

                return (True, self.domainGlobalAdmin, list(result)[0])
            else:
                return (False, 'INVALID_MAIL')
        except Exception, e:
            return (False, str(e))

    @decorators.require_global_admin
    def add(self, data):
        self.cn = data.get('cn', '')
        self.mail = web.safestr(data.get('mail')).strip().lower()

        if not iredutils.isEmail(self.mail):
            return (False, 'INVALID_MAIL')

        # Check admin exist.
        connutils = connUtils.Utils()
        if connutils.isAdminExists(self.mail):
            return (False, 'ALREADY_EXISTS')

        # Get domainGlobalAdmin setting.
        self.domainGlobalAdmin = web.safestr(data.get('domainGlobalAdmin', 'no'))
        if self.domainGlobalAdmin not in ['yes', 'no',]:
            self.domainGlobalAdmin = 'no'

        # Get language setting.
        preferredLanguage = web.safestr(data.get('preferredLanguage', 'en_US'))

        # Get new password.
        self.newpw = web.safestr(data.get('newpw'))
        self.confirmpw = web.safestr(data.get('confirmpw'))

        result = iredutils.verifyNewPasswords(self.newpw, self.confirmpw)

        if result[0] is True:
            self.passwd = result[1]
        else:
            return result

        try:
            self.conn.insert(
                'dbmail_admins',
                username=self.mail,
                name=self.cn,
                password=iredutils.getSQLPassword(self.passwd),
                language=preferredLanguage,
                created=iredutils.sqlNOW,
                active='1',
            )

            if self.domainGlobalAdmin == 'yes':
                self.conn.insert(
                    'dbmail_domain_admins',
                    username=self.mail,
                    domain='ALL',
                    created=iredutils.sqlNOW,
                    active='1',
                )

            web.logger(msg="Create admin: %s." % (self.mail), event='create',)
            return (True,)
        except Exception, e:
            return (False, str(e))

    @decorators.require_login
    def update(self, profile_type, mail, data):
        self.profile_type = web.safestr(profile_type)
        self.mail = web.safestr(mail)

        if not session.get('domainGlobalAdmin') and session.get('username') != self.mail:
            # Don't allow to view/update other admins' profile.
            return (False, 'PERMISSION_DENIED')

        if self.profile_type == 'general':
            # Get name
            self.cn = data.get('cn', '')

            # Get preferred language.
            preferredLanguage = str(data.get('preferredLanguage', 'en_US'))

            # Update in SQL db.
            try:
                self.conn.update(
                    'dbmail_admins',
                    where='username=%s' % web.sqlquote(self.mail),
                    name=self.cn,
                    language=preferredLanguage,
                )

                # Update language immediately.
                if session.get('username') == self.mail:
                    session['lang'] = preferredLanguage
            except Exception, e:
                return (False, str(e))

            if session.get('domainGlobalAdmin') is True:
                # Update account status
                accountStatus = '0'    # Disabled
                if 'accountStatus' in data.keys():
                    accountStatus = '1'    # Active

                try:
                    self.conn.update(
                        'dbmail_admins',
                        where='username=%s' % web.sqlquote(self.mail),
                        active=accountStatus,
                    )
                except Exception, e:
                    return (False, str(e))

                # Update global admin.
                self.domainGlobalAdmin = False
                if 'domainGlobalAdmin' in data.keys():
                    self.domainGlobalAdmin = True

                if self.domainGlobalAdmin is True:
                    try:
                        self.conn.delete(
                            'dbmail_domain_admins',
                            where='username=%s' % web.sqlquote(self.mail),
                        )

                        self.conn.insert(
                            'dbmail_domain_admins',
                            username=self.mail,
                            created=iredutils.sqlNOW,
                            domain='ALL',
                            active=accountStatus,
                        )
                    except Exception, e:
                        return (False, str(e))
                else:
                    try:
                        self.conn.delete(
                            'dbmail_domain_admins',
                            where='username=%s AND domain="ALL"' % web.sqlquote(self.mail),
                        )
                    except Exception, e:
                        return (False, str(e))

                # Update managed domains.
                # Get domains from web form.
                newmds = [str(v).lower() for v in data.get('domainName', []) if iredutils.isDomain(v)]
                if len(newmds) > 0:
                    try:
                        # Delete all managed domains.
                        self.conn.delete(
                            'dbmail_domain_admins',
                            where='username=%s AND domain <> "ALL"' % web.sqlquote(self.mail),
                        )

                        # Insert new domains.
                        for d in newmds:
                            self.conn.insert(
                                'dbmail_domain_admins',
                                username=self.mail,
                                domain=d,
                                active=accountStatus,
                                created=iredutils.sqlNOW,
                            )
                    except Exception, e:
                        return (False, str(e))

        elif self.profile_type == 'password':
            self.cur_passwd = str(data.get('oldpw', ''))
            self.newpw = web.safestr(data.get('newpw', ''))
            self.confirmpw = web.safestr(data.get('confirmpw', ''))

            # Verify new passwords.
            qr = iredutils.verifyNewPasswords(self.newpw, self.confirmpw)
            if qr[0] is True:
                self.passwd = iredutils.getSQLPassword(qr[1])
            else:
                return qr

            if session.get('domainGlobalAdmin') is not True:
                # Verify old password.
                auth = core.Auth()
                qr = auth.auth(username=self.mail, password=self.cur_passwd, verifyPassword=True,)
                if qr[0] is False:
                    return qr

            # Hash/Encrypt new password.
            try:
                self.conn.update(
                    'dbmail_admins',
                    where='username=%s' % web.sqlquote(self.mail),
                    password=self.passwd,
                )
            except Exception, e:
                raise web.seeother('/profile/admin/password/%s?msg=%s' % (self.mail, web.urlquote(e)))

        return (True,)
