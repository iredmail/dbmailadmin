# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from libs import iredutils, settings
from libs.dbmail_mysql import core, decorators, connUtils

cfg = web.iredconfig
session = web.config.get('_session')


if session.get('enablePolicyd'):
    from libs.policyd import throttle


class Domain(core.MySQLWrap):
    def __del__(self):
        pass

    @decorators.require_global_admin
    def enableOrDisableAccount(self, accounts, active=True):
        return self.setAccountStatus(accounts=accounts, active=active, accountType='domain',)

    def getAllDomains(self, columns=[],):
        """Get all domains. Return (True, [records])."""
        try:
            if columns:
                result = self.conn.select('dbmail_domains', what=','.join(columns))
            else:
                result = self.conn.select('dbmail_domains')

            return (True, list(result))
        except Exception, e:
            return (False, str(e))

    def getDomainAdmins(self, domain, mailOnly=False):
        self.domain = str(domain)

        if not iredutils.isDomain(self.domain):
            return (False, 'INVALID_DOMAIN_NAME')

        try:
            qr = self.conn.query(
                '''
                SELECT
                    dbmail_admins.username, dbmail_admins.name, dbmail_admins.language,
                    dbmail_admins.created, dbmail_admins.active
                FROM dbmail_admins
                LEFT JOIN dbmail_domain_admins ON (dbmail_domain_admins.username=dbmail_admins.username)
                WHERE dbmail_domain_admins.domain=$domain
                ''',
                vars={'domain': self.domain, },
            )
            if mailOnly is True:
                admins = []
                for adm in qr:
                    admins += [adm.username]
                return (True, admins)
            else:
                return (True, list(qr))
        except Exception, e:
            return (False, str(e))

    def getAllAliasDomains(self, domains, namesOnly=False,):
        if isinstance(domains, list):
            domains = [v.lower() for v in domains if iredutils.isDomain(v)]
        else:
            domains = str(domains)
            if not iredutils.isDomain(domains):
                return (False, 'INVALID_DOMAIN_NAME')
            else:
                domains = [domains]

        try:
            qr = self.conn.select('dbmail_alias_domains',
                                  vars={'domains': domains, },
                                  where='target_domain IN $domains',
                                 )
            if namesOnly is True:
                target_domains = {}
                for r in qr:
                    target_domain = web.safestr(r.target_domain)
                    if target_domain in target_domains:
                        target_domains[target_domain] += [web.safestr(r.alias_domain)]
                    else:
                        target_domains[target_domain] = [web.safestr(r.alias_domain)]
                return (True, target_domains)
            else:
                return (True, list(qr))
        except Exception, e:
            return (False, str(e))

    @decorators.require_domain_access
    def getCountsOfExistAccountsUnderDomain(self, domain, accountType='user'):
        if not iredutils.isDomain(domain):
            return (False, 'INVALID_DOMAIN_NAME')

        sql_vars = {'domain': domain, }
        if accountType == 'user':
            try:
                qr1 = self.conn.select(
                    'dbmail_users',
                    vars=sql_vars,
                    what='COUNT(user_idnr) AS mailbox_count',
                    where='domain = $domain AND user_idnr > 3',
                )
                mailbox_count = qr1[0].mailbox_count or 0

                # Get stored mailbox quota.
                qr2 = self.conn.select(
                    'dbmail_users',
                    vars=sql_vars,
                    what='SUM(maxmail_size) AS quota_count',
                    where='domain = $domain AND user_idnr > 3',
                )
                quota_count = qr2[0].quota_count or 0
                return (True, mailbox_count, quota_count)
            except Exception, e:
                return (False, str(e))
        elif accountType == 'alias':
            try:
                result = self.conn.select(
                    'dbmail_aliases_extra',
                    vars=sql_vars,
                    what='COUNT(id) AS alias_count',
                    where='domain = $domain',
                )
                result = list(result)
                return (True, result[0].alias_count)
            except Exception, e:
                return (False, str(e))
        else:
            return (False, 'INVALID_ACCOUNT_TYPE')

    @decorators.require_domain_access
    def getAllocatedQuotaSize(self, domain):
        try:
            result = self.conn.select(
                'dbmail_users',
                what='SUM(maxmail_size) AS total',
                where='domain = %s' % web.sqlquote(domain),
            )
            result = list(result)
            return (True, result[0].total or 0)
        except Exception, e:
            return (False, str(e))

    # List all domains under control.
    def listAccounts(self, cur_page=1):
        admin = session.get('username')

        page = int(cur_page) or 1

        sql_where = ''
        if session.get('domainGlobalAdmin') is not True:
            sql_where = ' WHERE dbmail_domain_admins.username = %s' % web.sqlquote(admin)

        # RAW sql command used to get records.
        rawSQLOfRecords = """
            SELECT
                a.domain, a.description, a.aliases, a.mailboxes, a.maxquota, a.quota,
                IFNULL(b.alias_count,0) AS alias_count,
                IFNULL(c.mailbox_count,0) AS mailbox_count,
                IFNULL(c.stored_quota,0) AS stored_quota,
                IFNULL(c.quota_count,0) AS quota_count
            FROM dbmail_domains AS a
            LEFT JOIN (SELECT domain, \
                        COUNT(id) AS alias_count \
                        FROM dbmail_aliases_extra \
                        GROUP BY domain) \
                        AS b ON (a.domain=b.domain)
            LEFT JOIN (SELECT domain, \
                        SUM(curmail_size) AS stored_quota, \
                        SUM(maxmail_size) AS quota_count, \
                        COUNT(user_idnr) AS mailbox_count \
                        FROM dbmail_users \
                        GROUP BY domain) \
                        AS c ON (a.domain=c.domain)
            LEFT JOIN dbmail_domain_admins ON (dbmail_domain_admins.domain=a.domain)
            %s
            GROUP BY a.domain
            ORDER BY a.domain
            LIMIT %d
            OFFSET %d
        """ % (sql_where, settings.PAGE_SIZE_LIMIT, (page - 1) * settings.PAGE_SIZE_LIMIT,)

        if self.isGlobalAdmin(admin):
            try:
                resultOfTotal = self.conn.select(
                    'dbmail_domains',
                    what='COUNT(domain) AS total',
                )

                resultOfRecords = self.conn.query(rawSQLOfRecords)
            except Exception, e:
                return (False, str(e))
        else:
            try:
                resultOfTotal = self.conn.select(
                    ['dbmail_domains', 'dbmail_domain_admins', ],
                    vars={'admin': admin, },
                    what='COUNT(dbmail_domains.domain) AS total',
                    where='dbmail_domains.domain = dbmail_domain_admins.domain AND dbmail_domain_admins.username = $admin',
                )

                resultOfRecords = self.conn.query(rawSQLOfRecords)
            except Exception, e:
                return (False, str(e))

        if len(resultOfTotal) == 1:
            self.total = resultOfTotal[0].total or 0
        else:
            self.total = 0

        return (True, self.total, list(resultOfRecords),)

    @decorators.require_global_admin
    def delete(self, domains=[]):
        if not isinstance(domains, list):
            return (False, 'INVALID_DOMAIN_NAME')

        self.domains = [str(v).lower()
                        for v in domains
                        if iredutils.isDomain(v)
                       ]
        sql_vars = {'domains': self.domains, }

        # Delete domain and related records.
        try:
            self.conn.delete(
                'dbmail_alias_domains',
                vars=sql_vars,
                where='alias_domain IN $domains OR target_domain IN $domains',
            )
            self.conn.delete(
                'dbmail_domain_admins',
                vars=sql_vars,
                where='domain IN $domains',
                )

            # Finally, delete from table `domain` to make sure all related
            # records were deleted.
            self.conn.delete(
                'dbmail_domains',
                vars=sql_vars,
                where='domain IN $domains',
                )

            for d in self.domains:
                web.logger(msg="Delete domain: %s." % (d), domain=d, event='delete',)
            return (True,)
        except Exception, e:
            return (False, str(e))

    @decorators.require_domain_access
    def simpleProfile(self, domain, columns=[]):
        self.domain = web.safestr(domain)

        if not iredutils.isDomain(self.domain):
            return (False, 'INVALID_DOMAIN_NAME')

        if len(columns) > 0:
            self.sql_what = ','.join(columns)
        else:
            self.sql_what = '*'

        try:
            qr = self.conn.select('dbmail_domains',
                                  vars={'domain': self.domain, },
                                  what=self.sql_what,
                                  where='domain=$domain',
                                 )

            if len(qr) == 1:
                # Return first list element.
                return (True, list(qr)[0])
            else:
                return (False, 'NO_SUCH_OBJECT')
        except Exception, e:
            return (False, str(e))

    @decorators.require_domain_access
    def profile(self, domain):
        self.domain = web.safestr(domain)

        if not iredutils.isDomain(self.domain):
            return (False, 'INVALID_DOMAIN_NAME')

        try:
            qr = self.conn.query('''
                SELECT
                    dbmail_domains.*,
                    COUNT(dbmail_users.user_idnr) AS mailbox_count,
                    COUNT(dbmail_aliases_extra.id) AS alias_count
                    -- sbcc.bcc_address AS sbcc_addr,
                    -- sbcc.active AS sbcc_active,
                    -- rbcc.bcc_address AS rbcc_addr,
                    -- rbcc.active AS rbcc_active,
                    -- alias.goto AS catchall,
                    -- alias.active AS catchall_active,
                    -- COUNT(DISTINCT mailbox.username) AS mailbox_count,
                FROM dbmail_domains
                LEFT JOIN dbmail_domain_admins ON (dbmail_domains.domain = dbmail_domain_admins.domain)
                -- LEFT JOIN sender_bcc_domain AS sbcc ON (sbcc.domain=dbmail_domains.domain)
                -- LEFT JOIN recipient_bcc_domain AS rbcc ON (rbcc.domain=dbmail_domains.domain)
                LEFT JOIN dbmail_users ON (dbmail_domains.domain = dbmail_users.domain)
                LEFT JOIN dbmail_aliases_extra ON (dbmail_domains.domain = dbmail_aliases_extra.alias)
                WHERE dbmail_domains.domain=$domain,
                GROUP BY
                    dbmail_domains.domain, dbmail_domains.description, dbmail_domains.aliases,
                    dbmail_domains.mailboxes, dbmail_domains.maxquota, dbmail_domains.quota,
                    dbmail_domains.transport, dbmail_domains.backupmx, dbmail_domains.created,
                    dbmail_domains.active
                ORDER BY dbmail_domains.domain
                LIMIT 1
                ''',
                vars={'domain': self.domain, },
            )

            if len(qr) == 1:
                # Return first list element.
                return (True, list(qr)[0])
            else:
                return (False, 'NO_SUCH_OBJECT')
        except Exception, e:
            return (False, str(e))

    @decorators.require_global_admin
    def add(self, data):
        self.domain = web.safestr(data.get('domainName', '')).strip().lower()

        # Get company/organization name.
        cn = data.get('cn', '')

        # Check domain name.
        if not iredutils.isDomain(self.domain):
            return (False, 'INVALID_DOMAIN_NAME')

        # Check whether domain name already exist (domainName, domainAliasName).
        connutils = connUtils.Utils()
        if connutils.isDomainExists(self.domain):
            return (False, 'ALREADY_EXISTS')

        # Add domain in database.
        try:
            self.conn.insert(
                'dbmail_domains',
                domain=self.domain,
                description=cn,
                transport=settings.DBMAIL_DEFAULT_DOMAIN_TRANSPORT,
            )
            web.logger(msg="Create domain: %s." % (self.domain), domain=self.domain, event='create',)
        except Exception, e:
            return (False, str(e))

        return (True,)

    @decorators.require_domain_access
    def update(self, domain, profile_type, data,):
        self.profile_type = str(profile_type)
        self.domain = str(domain)

        # Pre-defined.
        sql_vars = {'domain': self.domain, }
        updates = {'modified': iredutils.sqlNOW, }

        if self.profile_type == 'general':
            # Get name.
            cn = data.get('cn', '')
            updates['description'] = cn

            # Get default quota for new user.
            self.defaultQuota = str(data.get('defaultQuota'))
            if self.defaultQuota.isdigit():
                updates['defaultuserquota'] = int(self.defaultQuota)

            if session.get('domainGlobalAdmin') is True:
                # Get account status
                #if 'accountStatus' in data.keys():
                #    updates['active'] = 1
                #else:
                #    updates['active'] = 0

                # Get domain quota size.
                domainQuota = str(data.get('domainQuota', 0))
                if domainQuota.isdigit():
                    domainQuota = int(domainQuota)
                else:
                    domainQuota = 0

                if domainQuota > 0:
                    domainQuotaUnit = str(data.get('domainQuotaUnit', 'MB'))
                    if domainQuotaUnit == 'GB':
                        domainQuota = domainQuota * 1024
                    elif domainQuotaUnit == 'TB':
                        domainQuota = domainQuota * 1024 * 1024

                updates['maxquota'] = domainQuota

                # Update SQL db with columns: maxquota, active.
                try:
                    self.conn.update(
                        'dbmail_domains',
                        vars=sql_vars,
                        where='domain=$domain',
                        **updates
                    )
                except Exception, e:
                    return (False, str(e))

                # Get list of domain admins.
                domainAdmins = [str(v).lower()
                                for v in data.get('domainAdmin', [])
                                if iredutils.isEmail(str(v))
                               ]

                try:
                    # Delete all records first.
                    self.conn.delete('dbmail_domain_admins',
                                     vars=sql_vars,
                                     where='domain=$domain',
                                    )

                    # Add new admins.
                    if len(domainAdmins) > 0:
                        v = []
                        for adm in domainAdmins:
                            v += [{'username': adm,
                                  'domain': self.domain,
                                  'created': iredutils.sqlNOW,
                                  'active': 1,
                                 }]

                        self.conn.multiple_insert('dbmail_domain_admins', values=v,)
                except Exception, e:
                    return (False, str(e))

        elif self.profile_type == 'bcc':
            # Delete old records first.
            try:
                self.conn.delete('sender_bcc_domain', vars=sql_vars, where='domain=$domain', )
                self.conn.delete('recipient_bcc_domain', vars=sql_vars, where='domain=$domain', )
            except Exception, e:
                return (False, str(e))

            # Get bcc status
            self.rbcc_status = '0'
            if 'recipientbcc' in data.keys():
                self.rbcc_status = '1'

            self.sbcc_status = '0'
            if 'senderbcc' in data.keys():
                self.sbcc_status = '1'

            senderBccAddress = str(data.get('senderBccAddress', None))
            if iredutils.isEmail(senderBccAddress):
                try:
                    self.conn.insert('sender_bcc_domain',
                                     domain=self.domain,
                                     bcc_address=senderBccAddress,
                                     created=iredutils.sqlNOW,
                                     active=self.sbcc_status
                                    )
                except Exception, e:
                    return (False, str(e))

            recipientBccAddress = str(data.get('recipientBccAddress', None))
            if iredutils.isEmail(recipientBccAddress):
                try:
                    self.conn.insert('recipient_bcc_domain',
                                     domain=self.domain,
                                     bcc_address=recipientBccAddress,
                                     created=iredutils.sqlNOW,
                                     active=self.rbcc_status
                                    )
                except Exception, e:
                    return (False, str(e))

        elif self.profile_type == 'relay':
            self.defaultTransport = str(cfg.general.get('mtaTransport', 'dovecot'))
            self.transport = data.get('mtaTransport', self.defaultTransport)
            updates['transport'] = self.transport
            self.conn.update(
                'dbmail_domains',
                vars=sql_vars,
                where='domain=$domain',
                **updates
            )
        elif self.profile_type == 'catchall':
            # Delete old records first.
            try:
                self.conn.delete('alias',
                                 vars=sql_vars,
                                 where='address=$domain',
                                )
            except Exception, e:
                return (False, str(e))

            # Get list of destination addresses.
            catchallAddress = set([str(v).lower()
                                    for v in data.get('catchallAddress', '').split(',')
                                    if iredutils.isEmail(v)
                                  ])

            # Get enable/disable status.
            self.status = 0
            if 'accountStatus' in data.keys():
                self.status = 1

            if len(catchallAddress) > 0:
                try:
                    self.conn.insert(
                        'alias',
                        address=self.domain,
                        goto=','.join(catchallAddress),
                        domain=self.domain,
                        created=iredutils.sqlNOW,
                        active=self.status,
                    )
                except Exception, e:
                    return (False, str(e))
        elif self.profile_type == 'aliases':
            if session.get('domainGlobalAdmin') is True:
                # Delete old records first.
                try:
                    self.conn.delete(
                        'dbmail_alias_domains',
                        vars=sql_vars,
                        where='target_domain=$domain',
                    )
                except Exception, e:
                    return (False, str(e))

                # Get domain aliases from web form and store in LDAP.
                connutils = connUtils.Utils()
                aliasDomains = [str(v).lower()
                                for v in data.get('domainAliasName', [])
                                if not connutils.isDomainExists(v.lower())
                               ]

                if len(aliasDomains) > 0:
                    v = []
                    for ad in aliasDomains:
                        v += [{'alias_domain': ad,
                               'target_domain': self.domain,
                               'created': iredutils.sqlNOW,
                               'active': 1,
                              }]
                    try:
                        self.conn.multiple_insert(
                            'dbmail_alias_domains',
                            values=v,
                        )
                    except Exception, e:
                        return (False, str(e))

        elif self.profile_type == 'throttle':
            self.senderThrottlingSetting = throttle.getSenderThrottlingSettingFromForm(
                account='@' + self.domain,
                accountType='domain',
                form=data,
            )

            self.recipientThrottlingSetting = throttle.getRecipientThrottlingSettingFromForm(
                account='@' + self.domain,
                accountType='domain',
                form=data,
            )

            throttleLib = throttle.Throttle()
            try:
                throttleLib.updateThrottlingSetting(
                    account='@' + self.domain,
                    accountType='sender',
                    setting=self.senderThrottlingSetting,
                )

                throttleLib.updateThrottlingSetting(
                    account='@' + self.domain,
                    accountType='recipient',
                    setting=self.recipientThrottlingSetting,
                )
            except Exception, e:
                pass

        elif self.profile_type == 'advanced':
            if session.get('domainGlobalAdmin') is True:
                numberOfUsers = str(data.get('numberOfUsers'))
                numberOfAliases = str(data.get('numberOfAliases'))
                minPwLen = str(data.get('minPasswordLength'))
                maxPwLen = str(data.get('maxPasswordLength'))

                if numberOfUsers.isdigit() or numberOfUsers == '-1':
                    updates['mailboxes'] = int(numberOfUsers)

                if numberOfAliases.isdigit() or numberOfAliases == '-1':
                    updates['aliases'] = int(numberOfAliases)

                if minPwLen.isdigit():
                    updates['minpasswordlength'] = int(minPwLen)

                if numberOfUsers.isdigit():
                    updates['maxpasswordlength'] = int(maxPwLen)

                defaultGroups = [str(v).lower()
                                 for v in data.get('defaultList', [])
                                 if iredutils.isEmail(v)
                                ]

                if len(defaultGroups) > 0:
                    updates['defaultuseraliases'] = ','.join(defaultGroups)

                try:
                    self.conn.update(
                        'dbmail_domains',
                        vars=sql_vars,
                        where='domain=$domain',
                        **updates
                    )
                except Exception, e:
                    return (False, str(e))

        return (True,)
