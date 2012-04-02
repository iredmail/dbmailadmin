# encoding: utf-8

# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from libs import iredutils, settings
from libs.dbmail_mysql import core, decorators, connUtils, domain as domainlib, admin as adminlib

cfg = web.iredconfig
session = web.config.get('_session')


class Alias(core.MySQLWrap):
    def __del__(self):
        pass

    def getAllAliases(self, domain, columns=[],):
        """Get all aliases under domain. Return (True, [records])."""
        self.domain = str(domain)
        if not iredutils.isDomain(self.domain):
            raise web.seeother('/domains?msg=INVALID_DOMAIN_NAME')

        sql_vars = {'domain': self.domain, }
        try:
            if columns:
                result = self.conn.select(
                    'dbmail_aliases_extra',
                    vars=sql_vars,
                    where='domain=$domain',
                    what=','.join(columns),
                )
            else:
                result = self.conn.select(
                    'dbmail_aliases_extra',
                    vars=sql_vars,
                    where='domain=$domain',
                )

            return (True, list(result))
        except Exception, e:
            return (False, str(e))

    @decorators.require_domain_access
    @decorators.require_login
    def listAccounts(self, domain='', cur_page=1):
        '''List all users.'''
        if not iredutils.isDomain(domain):
            return (False, 'INVALID_DOMAIN_NAME')

        self.domain = str(domain)
        sql_vars = {'domain': self.domain, }

        try:
            resultOfRecords = self.conn.select(
                'dbmail_aliases_extra',
                vars=sql_vars,
                what='alias, name',
                where='domain=$domain',
                limit=settings.PAGE_SIZE_LIMIT,
                offset=(cur_page - 1) * settings.PAGE_SIZE_LIMIT,
            )
            records = list(resultOfRecords)
            return (True, len(records), records)
        except Exception, e:
            return (False, str(e))

    @decorators.require_domain_access
    def enableOrDisableAccount(self, domain, accounts, active=True):
        return self.setAccountStatus(accounts=accounts, active=active, accountType='alias',)

    @decorators.require_domain_access
    @decorators.require_login
    def delete(self, domain, mails=[]):
        self.domain = str(domain)
        if not iredutils.isDomain(self.domain):
            return (False, 'INVALID_DOMAIN_NAME')

        if not isinstance(mails, (list, tuple,)):
            return (False, 'INVALID_MAIL')

        self.mails = [str(v).lower()
                      for v in mails
                      if iredutils.isEmail(v) and str(v).endswith('@' + self.domain)
                     ]

        # Remove alias from domain.defaultuseraliases.
        # Get domain profile.
        domainLib = domainlib.Domain()
        qr = domainLib.simpleProfile(domain=self.domain, columns=['domain', 'defaultuseraliases', ])

        if qr[0] is True:
            self.domainProfile = qr[1]
        else:
            return qr

        self.defaultUserAliases = self.domainProfile.defaultuseraliases.split(',')

        # Remove from domain.defaultuseraliases.
        self.newDefaultAliases = [str(v).lower()
                                  for v in self.defaultUserAliases
                                  if v not in self.mails
                                 ]

        # Delete domain and related records.
        try:
            self.conn.delete('dbmail_aliases_extra', where='%s' % web.sqlors('alias = ', self.mails),)
            self.conn.delete('dbmail_aliases', where='%s' % web.sqlors('alias = ', self.mails),)
            self.conn.update('dbmail_domains',
                             vars={'domain': self.domain, },
                             defaultuseraliases=','.join(self.newDefaultAliases),
                             modified=iredutils.getGMTTime(),
                             where='domain = $domain',
                            )

            web.logger(
                msg="Delete mail alias: %s." % ', '.join(self.mails),
                domain=self.domain,
                event='delete',
            )
            return (True,)
        except Exception, e:
            return (False, str(e))

    @decorators.require_domain_access
    def add(self, domain, data):
        # Get domain name, username, cn.
        self.domain = web.safestr(data.get('domainName')).strip().lower()
        self.username = web.safestr(data.get('listname')).strip().lower()
        self.mail = self.username + '@' + self.domain

        if self.domain != domain:
            return (False, 'PERMISSION_DENIED')

        if not iredutils.isDomain(self.domain):
            return (False, 'INVALID_DOMAIN_NAME')

        if not iredutils.isEmail(self.mail):
            return (False, 'INVALID_MAIL')

        # Define columns and values used to insert.
        columns = {'domain': self.domain, 'alias': self.mail, }

        # Check account existing.
        connutils = connUtils.Utils()
        if connutils.isEmailExists(mail=self.mail):
            return (False, 'ALREADY_EXISTS')

        # Get domain profile.
        domainLib = domainlib.Domain()
        resultOfDomainProfile = domainLib.profile(domain=self.domain)

        if resultOfDomainProfile[0] is True:
            self.domainProfile = resultOfDomainProfile[1]
        else:
            return resultOfDomainProfile

        # Check account limit.
        adminLib = adminlib.Admin()
        numberOfExistAccounts = adminLib.getNumberOfManagedAccounts(accountType='alias', domains=[self.domain])

        if self.domainProfile.aliases == -1:
            return (False, 'NOT_ALLOWED')
        elif self.domainProfile.aliases > 0:
            if self.domainProfile.aliases <= numberOfExistAccounts:
                return (False, 'EXCEEDED_DOMAIN_ACCOUNT_LIMIT')

        # Get display name from <form>
        columns['name'] = data.get('cn', '')

        try:
            # Store new user in required SQL DBs.
            self.conn.insert(
                'dbmail_aliases_extra',
                **columns
            )
            web.logger(msg="Create mail alias: %s." % (self.mail), domain=self.domain, event='create',)
            return (True,)
        except Exception, e:
            return (False, str(e))

    @decorators.require_domain_access
    @decorators.require_login
    def profile(self, domain, mail):
        self.domain = str(domain)
        self.mail = str(mail)
        if not iredutils.isDomain(self.domain):
            return (False, 'INVALID_DOMAIN_NAME')

        if not iredutils.isEmail(self.mail):
            return (False, 'INVALID_MAIL')

        if not self.mail.endswith('@' + self.domain):
            raise web.seeother('/domains?msg=PERMISSION_DENIED')

        try:
            result = self.conn.select(
                'dbmail_aliases_extra',
                vars={'mail': self.mail, },
                where='alias = $mail',
                limit=1,
            )
            return (True, list(result)[0])
        except Exception, e:
            return (False, str(e))

    @decorators.require_domain_access
    @decorators.require_login
    def getAliasMembers(self, mail):
        self.mail = str(mail)
        members = []

        if not iredutils.isEmail(self.mail):
            return (False, 'INVALID_MAIL')

        try:
            qr = self.conn.select(
                'dbmail_aliases',
                vars={'mail': self.mail, },
                what='deliver_to',
                where='alias = $mail',
            )
            if qr:
                members = [str(rcd.deliver_to) for rcd in qr if iredutils.isEmail(str(rcd.deliver_to))]

            return (True, members)
        except Exception, e:
            return (False, str(e))

    # Update mail alias profile.
    @decorators.require_domain_access
    @decorators.require_login
    def update(self, profile_type, mail, data,):
        self.profile_type = str(profile_type)
        self.mail = str(mail)
        self.domain = self.mail.split('@', 1)[-1]

        if not iredutils.isEmail(self.mail) or not iredutils.isDomain(self.domain):
            return (False, 'INVALID_MAIL')

        # Pre-defined.
        sql_vars = {'mail': self.mail, 'domain': self.domain, }
        values = {}

        # Get cn.
        self.cn = data.get('cn', '')
        values['name'] = self.cn

        # Get accountStatus.
        #self.status = 0     # Disabled.
        #if 'accountStatus' in data.keys():
        #    self.status = 1     # Enabled.
        #values['active'] = self.status

        # Get access policy.
        #self.accessPolicy = str(data.get('accessPolicy', ''))
        #if self.accessPolicy in settings.SQL_ALIAS_ACCESS_POLICIES:
        #    values['accesspolicy'] = self.accessPolicy

        # Get members & moderators from web form.
        self.mailForwardingAddresses = [
            str(v).lower()
            for v in data.get('mailForwardingAddress', [])
            if iredutils.isEmail(str(v))
        ]
        #self.moderators = [
        #    str(v).lower()
        #    for v in data.get('moderators', [])
        #    if iredutils.isEmail(str(v))
        #]

        # Get mail forwarding addresses & moderators from form.
        self.newMailForwardingAddresses = set(
            str(v).strip().lower()
            for v in data.get('newMailForwardingAddresses').splitlines()
            if iredutils.isEmail(str(v).strip())
        )
        #self.newModerators = set(
        #    str(v).strip().lower()
        #    for v in data.get('newModerators').splitlines()
        #    if iredutils.isEmail(str(v).strip())
        #)

        # Get union set of old/new alias members.
        self.allMembers = set(self.mailForwardingAddresses) | self.newMailForwardingAddresses
        #self.allModerators = set(self.moderators) | self.newModerators

        # Remove non-exist accounts in same domain.
        # Get alias members & moderators which in same domain.
        self.membersInDomain = [v for v in self.allMembers if v.endswith('@' + self.domain)]
        self.membersNotInDomain = [v for v in self.allMembers if not v.endswith('@' + self.domain)]
        #self.moderatorsInDomain = [v for v in self.allModerators if v.endswith('@' + self.domain)]
        #self.moderatorsNotInDomain = [v for v in self.allModerators if not v.endswith('@' + self.domain)]

        # Re-generate list of alias members, remove non-exist members.
        if len(self.membersInDomain) > 0:
            qr = self.conn.select(
                'dbmail_users',
                vars=sql_vars,
                what='userid',
                where='domain = $domain AND %s' % (web.sqlors('userid = ', self.membersInDomain)),
            )
            self.membersInDomain = [str(rcd.userid) for rcd in qr]

        # Get alias moderators.
        """
        if len(self.moderatorsInDomain) > 0:
            qr = self.conn.select(
                'dbmail_users',
                what='userid',
                where='domain = %s AND ' % (
                    web.sqlquote(self.domain),
                    web.sqlors('userid = ', self.moderatorsInDomain),
                ),
            )
            self.moderatorsInDomain = []
            for i in qr:
                self.moderatorsInDomain += [str(i.userid)]

        values['moderators'] = ','.join(self.moderatorsInDomain + self.moderatorsNotInDomain)
        """

        try:
            self.conn.update(
                'dbmail_aliases_extra',
                vars=sql_vars,
                where='alias=$mail',
                **values
            )

            self.conn.delete('dbmail_aliases',
                             vars=sql_vars,
                             where='alias = $mail',
                            )

            if self.membersInDomain or self.membersNotInDomain:
                sql_values = [{'alias': self.mail, 'deliver_to': member, }
                               for member in self.membersInDomain + self.membersNotInDomain
                              ]
                self.conn.multiple_insert('dbmail_aliases', sql_values)

            return (True,)
        except Exception, e:
            return (False, str(e))
