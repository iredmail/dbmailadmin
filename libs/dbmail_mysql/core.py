# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from libs import iredutils, md5crypt

cfg = web.iredconfig
session = web.config.get('_session')

class MySQLWrap:
    def __init__(self, app=web.app, session=session, **settings):
        # Initial DB connection and cursor.
        try:
            self.conn = web.database(
                dbn='mysql',
                host=cfg.dbmail.get('host', '127.0.0.1'),
                port=int(cfg.dbmail.get('port', 3306)),
                db=cfg.dbmail.get('db', 'vmail'),
                user=cfg.dbmail.get('user', 'vmailadmin'),
                pw=cfg.dbmail.get('passwd', ''),
                charset='utf8',
            )
            self.conn.supports_multiple_insert = True
        except:
            return False

    # Validators.
    def isGlobalAdmin(self, admin=None,):
        if admin is None:
            return False
        elif admin == session.get('username'):
            if session.get('domainGlobalAdmin') is True:
                return True
            else:
                return False

        admin = str(admin)

        # Not logged admin.
        try:
            result = self.conn.select(
                'dbmail_domain_admins',
                what='username',
                where='''username=%s AND domain="ALL"''' % web.sqlquote(admin),
                limit=1,
            )
            if len(result) == 1:
                return True
            else:
                return False
        except Exception, e:
            return False

    def isDomainAdmin(self, domain, admin=session.get('username'),):
        if not iredutils.isDomain(domain) or not iredutils.isEmail(admin):
            return False

        if admin == session.get('username') and session.get('domainGlobalAdmin') is True:
            return True

        try:
            result = self.conn.select(
                'dbmail_domain_admins',
                what='username',
                where='domain=%s AND username=%s AND active=1' % (
                    web.sqlquote(domain),
                    web.sqlquote(admin),
                ),
                limit=1,
            )
            if len(result) == 1:
                return True
            else:
                return False
        except Exception, e:
            return False

    def setAccountStatus(self, accounts, accountType, active=True):
        # accounts must be a list/tuple.
        # accountType in ['domain', 'user', 'admin', 'alias',]
        # active: True -> active, False -> disabled
        if not len(accounts) > 0:
            return (True,)

        accountType = str(accountType)
        if active is True:
            active = 1
            action = 'Active'
        else:
            active = 0
            action = 'Disable'

        if accountType == 'domain':
            accounts = [str(v) for v in accounts if iredutils.isDomain(v)]
            try:
                self.conn.update(
                    'dbmail_domains',
                    where='domain IN %s' % (web.sqlquote(accounts)),
                    active=active,
                )
            except Exception, e:
                return (False, str(e))
        elif accountType == 'user':
            accounts = [str(v) for v in accounts if iredutils.isEmail(v)]
            try:
                self.conn.update(
                    'dbmail_users',
                    where='userid IN %s' % (web.sqlquote(accounts)),
                    active=active,
                )
            except Exception, e:
                return (False, str(e))
        elif accountType == 'admin':
            accounts = [str(v) for v in accounts if iredutils.isEmail(v)]
            try:
                self.conn.update(
                    'dbmail_admins',
                    where='username IN %s' % (web.sqlquote(accounts)),
                    active=active,
                )
            except Exception, e:
                return (False, str(e))
        elif accountType == 'alias':
            accounts = [str(v) for v in accounts if iredutils.isEmail(v)]
            try:
                self.conn.update(
                    'alias',
                    where='address IN %s' % (web.sqlquote(accounts)),
                    active=active,
                )
            except Exception, e:
                return (False, str(e))
        else:
            pass

        try:
            web.logger(
                msg="%s %s: %s." % (action, accountType, ', '.join(accounts)),
                event=action.lower(),
            )
        except:
            pass
        return (True,)

    def deleteAccounts(self, accounts, accountType,):
        # accounts must be a list/tuple.
        # accountType in ['domain', 'user', 'admin', 'alias',]
        if not accounts:
            return (True,)

        accountType = str(accountType)

        if accountType == 'domain':
            accounts = [str(v) for v in accounts if iredutils.isDomain(v)]
            try:
                self.conn.delete('dbmail_domains', where='domain IN %s' % (web.sqlquote(accounts)),)
            except Exception, e:
                return (False, str(e))
        elif accountType == 'user':
            accounts = [str(v) for v in accounts if iredutils.isEmail(v)]
            try:
                self.conn.delete('dbmail_users', where='userid IN %s' % (web.sqlquote(accounts)),)
            except Exception, e:
                return (False, str(e))
        elif accountType == 'admin':
            accounts = [str(v) for v in accounts if iredutils.isEmail(v)]
            try:
                self.conn.delete('dbmail_admins', where='username IN %s' % (web.sqlquote(accounts)),)
            except Exception, e:
                return (False, str(e))
        elif accountType == 'alias':
            accounts = [str(v) for v in accounts if iredutils.isEmail(v)]
            try:
                self.conn.delete('alias', where='address IN %s' % (web.sqlquote(accounts)),)
            except Exception, e:
                return (False, str(e))
        else:
            pass

        try:
            web.logger(
                msg="Delete %s: %s." % (accountType, ', '.join(accounts)),
                event='delete',
            )
        except:
            pass
        return (True,)

    def getUsedBytesMessages(self, domain=None):
        """Return (messages, bytes)"""
        if domain is None:
            resultOfSum = self.conn.query(
                '''
                SELECT SUM(curmail_size) AS bytes
                FROM dbmail_users
                '''
            )
            counterOfSum = resultOfSum[0]
        else:
            if not iredutils.isDomain(domain):
                return (0, 0)

            # Check domain access
            if self.isDomainAdmin(domain=domain, admin=session.get('username'),):
                resultOfSum = self.conn.query(
                    '''
                    SELECT SUM(curmail_size) AS bytes
                    FROM dbmail_users
                    WHERE domain = %s
                    ''' % web.sqlquote(domain)
                )
                counterOfSum = resultOfSum[0]
            else:
                return (0, 0)

        return (None, counterOfSum.bytes)


class Auth(MySQLWrap):
    def auth(self, username, password, accountType='admin', verifyPassword=False,):
        if not iredutils.isEmail(username):
            return (False, 'INVALID_USERNAME')

        if len(password) == 0:
            return (False, 'EMPTY_PASSWORD')

        # Query account from SQL database.
        if accountType == 'admin':
            result = self.conn.select(
                'dbmail_admins',
                where="username=%s AND active=1" % web.sqlquote(username),
                limit=1,
            )
        elif accountType == 'user':
            result = self.conn.select(
                'dbmail_users',
                where="userid=%s AND active=1" % web.sqlquote(username),
                limit=1,
            )
        else:
            return (False, 'INVALID_ACCOUNT_TYPE')

        if len(result) != 1:
            # Account not found.
            # Do NOT return msg like 'Account does not ***EXIST***', crackers
            # can use it to verify valid accounts.
            return (False, 'INVALID_CREDENTIALS')

        # It's a valid account.
        record = result[0]
        password_sql = str(record.password)

        # Verify password.
        authenticated = False
        if password_sql.startswith('$') and len(password_sql) == 34 and password_sql.count('$') == 3:
            # Password is considered as a MD5 password (with salt).
            # Get salt string from password which stored in SQL.
            tmpsalt = password_sql.split('$')
            tmpsalt[-1] = ''
            salt = '$'.join(tmpsalt)

            if md5crypt.md5crypt(password, salt) == password_sql:
                authenticated = True

        elif password_sql.upper().startswith('{PLAIN}'):
            # Plain password with prefix '{PLAIN}'.
            if password_sql.split('}', 1)[-1] == password:
                authenticated = True

        elif password_sql == password:
            # Plain password.
            authenticated = True

        # Compare passwords.
        if authenticated is False:
            return (False, 'INVALID_CREDENTIALS')

        if verifyPassword is not True:
            session['username'] = username
            session['logged'] = True
            # Set preferred language.
            session['lang'] = str(record.language) or 'en_US'

            # Set session['domainGlobalAdmin']
            try:
                result = self.conn.select(
                    'dbmail_domain_admins',
                    what='domain',
                    where='''username=%s AND domain="ALL"''' % web.sqlquote(username),
                    limit=1,
                )
                if len(result) == 1:
                    session['domainGlobalAdmin'] = True
            except:
                pass

        return (True,)


class MySQLDecorators(MySQLWrap):
    def __del__(self):
        pass

    def require_global_admin(self, func):
        def proxyfunc(self, *args, **kw):
            if session.get('domainGlobalAdmin') is True:
                return func(self, *args, **kw)
            else:
                return False
        return proxyfunc

    def require_domain_access(self, func):
        def proxyfunc(self, *args, **kw):
            if 'mail' in kw.keys() and iredutils.isEmail(kw.get('mail')):
                self.domain = web.safestr(kw['mail']).split('@')[-1]
            elif 'domain' in kw.keys() and iredutils.isDomain(kw.get('domain')):
                self.domain = web.safestr(kw['domain'])
            else:
                return False

            self.admin = session.get('username')
            if not iredutils.isEmail(self.admin):
                return False

            # Check domain global admin.
            if session.get('domainGlobalAdmin') is True:
                return func(self, *args, **kw)
            else:
                # Check whether is domain admin.
                try:
                    result = self.conn.select(
                        'dbmail_domain_admins',
                        what='username',
                        where='''username=%s AND domain IN %s''' % (
                            web.sqlquote(self.admin),
                            web.sqlquote([self.domain, 'ALL']),
                        ),
                    )
                except Exception, e:
                    result = {}

                if len(result) != 1:
                    return func(self, *args, **kw)
                else:
                    raise web.seeother('/users' + '?msg=PERMISSION_DENIED&domain=' + self.domain)
        return proxyfunc
