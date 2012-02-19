# encoding: utf-8

# Author: Zhang Huangbin <zhb@iredmail.org>

import web

from libs import iredutils
from libs.dbmail_mysql import core

session = web.config.get('_session')


class Utils(core.MySQLWrap):

    def isDomainExists(self, domain):
        # Return True if account is invalid or exist.
        domain = str(domain)
        if not iredutils.isDomain(domain):
            return True

        try:
            result = self.conn.select(
                'dbmail_domains',
                what='domain',
                where='domain = %s' % web.sqlquote(domain),
                limit=1,
            )

            if len(result) > 0:
                # Exists.
                return True

            result = self.conn.select(
                'dbmail_alias_domains',
                what='alias_domain',
                where='alias_domain = %s' % web.sqlquote(domain),
                limit=1,
            )

            if len(result) > 0:
                # Alias domain exists.
                return True
            else:
                return False
        except:
            # Return True as exist to not allow to create new domain/account.
            return True

    def isAdminExists(self, mail):
        # Return True if account is invalid or exist.
        mail = str(mail)
        if not iredutils.isEmail(mail):
            return True

        try:
            result = self.conn.select(
                'dbmail_admins',
                what='username',
                where='username = %s' % web.sqlquote(mail),
                limit=1,
            )

            if len(result) > 0:
                # Exists.
                return True
            else:
                return False
        except:
            # Return True as exist to not allow to create new domain/account.
            return True

    # Check whether account exist or not.
    def isEmailExists(self, mail):
        # Return True if account is invalid or exist.
        self.mail = web.safestr(mail)

        if not iredutils.isEmail(self.mail):
            return True

        self.sqlMail = web.sqlquote(self.mail)

        try:
            resultOfMailbox = self.conn.select(
                'dbmail_users',
                what='userid',
                where='userid=%s' % self.sqlMail,
                limit=1,
            )

            resultOfAlias = self.conn.select(
                'dbmail_aliases',
                what='alias',
                where='alias=%s' % self.sqlMail,
                limit=1,
            )

            if resultOfMailbox or resultOfAlias:
                return True
            else:
                return False

        except Exception, e:
            return True

    def getAllGlobalAdmins(self):
        try:
            qr = self.conn.select('dbmail_domain_admins',
                                  what='username,domain',
                                  where="domain='ALL'",
                                 )
            result = []
            for r in qr:
                result += [str(r.username).lower()]
            return (True, result)
        except Exception, e:
            return (False, str(e))

    # Get domains under control.
    def getManagedDomains(self, admin, domainNameOnly=False, listedOnly=False,):
        self.admin = web.safestr(admin)

        if not iredutils.isEmail(self.admin):
            return (False, 'INCORRECT_USERNAME')

        self.sql_where = ''
        self.sql_left_join = ''
        if listedOnly is True:
            self.sql_where = 'AND dbmail_domain_admins.username=%s' % web.sqlquote(self.admin)
        else:
            self.sql_left_join = 'OR dbmail_domain_admins.domain="ALL"' % web.sqlquote(self.admin)

        try:
            result = self.conn.query(
                """
                SELECT dbmail_domains.domain
                FROM dbmail_domains
                LEFT JOIN dbmail_domain_admins ON (dbmail_domains.domain=dbmail_domain_admins.domain %s)
                WHERE dbmail_domain_admins.username=%s %s
                ORDER BY dbmail_domain_admins.domain
                """ % (self.sql_left_join, web.sqlquote(self.admin), self.sql_where)
            )

            if domainNameOnly is True:
                domains = []
                for i in result:
                    if iredutils.isDomain(i.domain):
                        domains += [str(i.domain).lower()]

                return (True, domains)
            else:
                return (True, list(result))
        except Exception, e:
            return (False, str(e))


    # Search accounts with display name, email.
    def search(self, searchString, accountType=[], accountStatus=[],):
        """Return search result in dict.

        (True, {
                'domain': sql_query_result,
                'user': sql_query_result,
                ...
                }
        )
        """

        s = searchString
        searchString = web.sqlquote('%%'+s+'%%')
        searchStringExcludeDomain = web.sqlquote('%%'+s+'%%@%%')

        if len(accountType) == 0:
            return (True, {})

        sql_append_status = ''
        sql_append_domains = ''
        if len(accountStatus) == 1:
            if 'active' in accountStatus:
                sql_append_status = ' AND active=1'
            elif 'disabled' in accountStatus:
                sql_append_status = ' AND active=0'

        # Get managed domains.
        if not session.get('domainGlobalAdmin'):
            managedDomains = []
            qr = self.getManagedDomains(
                admin=session.get('username'),
                domainNameOnly=True,
                listedOnly=True,
            )
            if qr[0] is True:
                managedDomains = qr[1]
                sql_append_domains = ' AND domain in %s' % web.sqlquote(managedDomains)
            else:
                raise web.seeother('/search?msg=%s' % web.urlquote(qr[1]))

        # Pre-define default values.
        result = {
            'admin': [],
            'user': [],
            'alias': [],
            'allGlobalAdmins': [], # List of email addresses of global admins.
        }

        # SQL query result sets.
        qr_admin = {}
        qr_user = {}
        qr_alias = {}
        allGlobalAdmins = []

        # Search admin accounts.
        if 'admin' in accountType and session.get('domainGlobalAdmin') is True:
            qr_admin = self.conn.select(
                'dbmail_admins',
                what='username,name,active',
                where='(username LIKE %s OR name LIKE %s) %s' % (
                    searchString, searchString, sql_append_status,
                ),
                order='username',
            )

        # Search user accounts.
        if 'user' in accountType:
            qr_user = self.conn.select(
                'dbmail_users',
                what='userid,name,maxmail_size,curmail_size,active',
                where='(userid LIKE %s OR name LIKE %s) %s %s' % (
                    searchStringExcludeDomain, searchStringExcludeDomain,
                    sql_append_status, sql_append_domains,
                ),
                order='user_idnr',
            )

        # Search alias accounts.
        if 'alias' in accountType:
            qr_alias= self.conn.select(
                ['alias'],
                what='address,name,accesspolicy,domain,active',
                where='(address LIKE %s OR name LIKE %s) AND address <> goto %s %s' % (
                    searchStringExcludeDomain, searchStringExcludeDomain,
                    sql_append_status, sql_append_domains,
                ),
                order='address',
            )

        if len(qr_admin) > 0:
            result['admin'] = iredutils.convertSQLQueryRecords(qr_admin) or []

            # Get all global admin accounts.
            if len(qr_admin) > 0:
                qr = self.getAllGlobalAdmins()
                if qr[0] is True:
                    allGlobalAdmins = qr[1]

            result['allGlobalAdmins'] = allGlobalAdmins

        if len(qr_user) > 0:
            result['user'] = iredutils.convertSQLQueryRecords(qr_user) or []

        if len(qr_alias) > 0:
            result['alias'] = iredutils.convertSQLQueryRecords(qr_alias) or []

        if len(result) > 0:
            return (True, result)
        else:
            return (False, [])