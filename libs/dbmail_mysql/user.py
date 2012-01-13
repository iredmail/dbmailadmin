# encoding: utf-8

# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from libs import iredutils, settings
from libs.dbmail_mysql import core, decorators, connUtils, domain as domainlib, admin as adminlib

cfg = web.iredconfig
session = web.config.get('_session', {})

if session.get('enablePolicyd'):
    from libs.policyd import throttle


ENABLED_SERVICES = [
    'enablesmtp', 'enablesmtpsecured',
    'enablepop3', 'enablepop3secured',
    'enableimap', 'enableimapsecured',
    'enablemanagesieve', 'enablemanagesievesecured',
    'enablesieve', 'enablesievesecured',
    'enabledeliver', 'enableinternal',
]

class User(core.MySQLWrap):
    def __del__(self):
        pass

    @decorators.require_domain_access
    @decorators.require_login
    def listAccounts(self, domain, cur_page=1):
        '''List all users.'''
        if not iredutils.isDomain(domain):
            return (False, 'INVALID_DOMAIN_NAME')

        domain = str(domain)
        connutils = connUtils.Utils()
        if not connutils.isDomainExists(domain):
            return (False, 'PERMISSION_DENIED')

        # Pre-defined.
        total = 0

        try:
            resultOfTotal = self.conn.select(
                'dbmail_users',
                what='COUNT(userid) AS total',
                where='domain=%s' % web.sqlquote(domain),
            )
            if len(resultOfTotal) == 1:
                total = resultOfTotal[0].total or 0

            resultOfRecords = self.conn.select(
                'dbmail_users',
                # Just query what we need to reduce memory use.
                what='userid,name,curmail_size,maxmail_size,last_login',
                where='domain=%s' % web.sqlquote(domain),
                order='userid ASC',
                limit=settings.PAGE_SIZE_LIMIT,
                offset=(cur_page-1) * settings.PAGE_SIZE_LIMIT,
            )

            return (True, total, list(resultOfRecords))
        except Exception, e:
            return (False, str(e))

    @decorators.require_domain_access
    def enableOrDisableAccount(self, domain, accounts, active=True):
        return self.setAccountStatus(accounts=accounts, active=active, accountType='user',)

    @decorators.require_domain_access
    def delete(self, domain, mails=[]):
        self.domain = str(domain)
        if not iredutils.isDomain(self.domain):
            return (False, 'INVALID_DOMAIN_NAME')

        if not isinstance(mails, list):
            return (False, 'INVALID_MAIL')

        self.mails = [str(addr).lower() for addr in mails if iredutils.isEmail(addr) and str(addr).endswith('@'+self.domain)]
        if not self.mails:
            return (False, 'INVALID_MAIL')

        # Delete domain and related records.
        try:
            # Delete from aliases.
            self.conn.delete('dbmail_aliases', where='%s' % web.sqlors('deliver_to = ', self.mails))
            self.conn.delete('dbmail_aliases', where='%s' % web.sqlors('alias = ', self.mails))

            # Delete user record.
            self.conn.delete('dbmail_users', where='%s' % web.sqlors('userid = ', self.mails))

            #self.conn.delete('recipient_bcc_user', where='username IN %s' % sqlquoted_mails)
            #self.conn.delete('sender_bcc_user', where='username IN %s' % sqlquoted_mails)

            web.logger(
                msg="Delete user: %s." % ', '.join(self.mails),
                domain=self.domain,
                event='delete',
            )

            return (True,)
        except Exception, e:
            return (False, str(e))

    @decorators.require_domain_access
    def profile(self, domain, mail):
        self.mail = web.safestr(mail)
        self.domain = self.mail.split('@', 1)[-1]

        if self.domain != domain:
            raise web.seeother('/domains?msg=PERMISSION_DENIED')

        if not self.mail.endswith('@' + self.domain):
            raise web.seeother('/domains?msg=PERMISSION_DENIED')

        try:
            result = self.conn.select('dbmail_users',
                                      where='userid = %s' % web.sqlquote(self.mail),
                                      limit=1,
                                     )
            if result:
                return (True, list(result)[0])
            else:
                return (False, 'INVALID_MAIL')
        except Exception, e:
            return (False, str(e))

    @decorators.require_domain_access
    def add(self, domain, data):
        # Get domain name, username, cn.
        self.domain = web.safestr(data.get('domainName')).strip().lower()
        self.username = web.safestr(data.get('username')).strip().lower()
        self.mail = self.username + '@' + self.domain
        sqlquoted_mail = web.sqlquote(self.mail)

        if not iredutils.isDomain(self.domain):
            return (False, 'INVALID_DOMAIN_NAME')

        if self.domain != domain:
            return (False, 'PERMISSION_DENIED')

        if not iredutils.isEmail(self.mail):
            return (False, 'INVALID_MAIL')

        # Check account existing.
        connutils = connUtils.Utils()
        if connutils.isEmailExists(self.mail):
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
        numberOfExistAccounts = adminLib.getNumberOfManagedAccounts(accountType='user', domains=[self.domain])

        if self.domainProfile.mailboxes == -1:
            return (False, 'NOT_ALLOWED')
        elif self.domainProfile.mailboxes > 0:
            if self.domainProfile.mailboxes <= numberOfExistAccounts:
                return (False, 'EXCEEDED_DOMAIN_ACCOUNT_LIMIT')

        columns = {'userid': self.mail, 'domain': self.domain,}

        # Check spare quota and number of spare account limit.
        # Get quota from form.
        self.mailQuota = str(data.get('mailQuota')).strip()
        self.defaultUserQuota = self.domainProfile.get('defaultuserquota', 0)

        if self.mailQuota.isdigit():
            self.mailQuota = int(self.mailQuota)
        else:
            self.mailQuota = self.defaultUserQuota

        # Re-calculate mail quota if this domain has max quota limit.
        if self.domainProfile.maxquota > 0:
            # Get used quota.
            qr = domainLib.getAllocatedQuotaSize(domain=self.domain)
            if qr[0] is True:
                self.allocatedQuota = qr[1]
            else:
                return qr

            spareQuota = self.domainProfile.maxquota - self.allocatedQuota/1024/1024

            if spareQuota > 0:
                if spareQuota < self.mailQuota:
                    self.mailQuota = spareQuota
            else:
                # No enough quota.
                return (False, 'EXCEEDED_DOMAIN_QUOTA_SIZE')

        columns['maxmail_size'] = self.mailQuota * 1024 * 1024

        #
        # Get password from <form>.
        #
        newpw = web.safestr(data.get('newpw', ''))
        confirmpw = web.safestr(data.get('confirmpw', ''))

        # Get password length limit from domain profile or global setting.
        self.minPasswordLength = self.domainProfile.get('minpasswordlength',cfg.general.get('min_passwd_length', '0'))
        self.maxPasswordLength = self.domainProfile.get('maxpasswordlength', cfg.general.get('max_passwd_length', '0'))

        resultOfPW = iredutils.verifyNewPasswords(
            newpw,
            confirmpw,
            min_passwd_length=self.minPasswordLength,
            max_passwd_length=self.maxPasswordLength,
        )
        if resultOfPW[0] is True:
            if 'storePasswordInPlainText' in data:
                columns['passwd'] = iredutils.getSQLPassword(resultOfPW[1], pwscheme='PLAIN')
                columns['encryption_type'] = ''
            else:
                columns['passwd'] = iredutils.getSQLPassword(resultOfPW[1])
                columns['encryption_type'] = settings.SQL_DEFAULT_PASSWD_SCHEME.lower()

        else:
            return resultOfPW

        # Get display name from <form>
        columns['name'] = data.get('cn', '')

        # Assign new user to default mail aliases.
        assignedAliases = [str(addr).lower()
                           for addr in str(self.domainProfile.defaultuseraliases).split(',')
                           if iredutils.isEmail(addr)
                          ]

        try:
            # Store new user in SQL db.
            self.conn.insert(
                'dbmail_users',
                **columns
            )

            # Get dbmail_users.user_idnr.
            qr = self.conn.select('dbmail_users',
                                  what='user_idnr,client_idnr',
                                  where='userid=%s' % sqlquoted_mail,
                                  limit=1,
                                 )
            p = qr[0]
            user_idnr, client_idnr = p.user_idnr, p.client_idnr

            self.conn.insert('dbmail_aliases',
                             alias=self.mail,
                             deliver_to=user_idnr,
                             client_idnr=client_idnr,
                            )

            # Create and subscribe to default IMAP folders.
            if settings.DBMAIL_CREATE_DEFAULT_IMAP_FOLDERS:
                # Create default IMAP folders.
                imap_folders = ['(%d, "%s")' % (user_idnr, fld) for fld in settings.DBMAIL_DEFAULT_IMAP_FOLDERS]
                self.conn.query('''INSERT INTO dbmail_mailboxes (owner_idnr, name) VALUES %s''' % ','.join(imap_folders))

                # Subscribe to folders by default.
                self.conn.query('''INSERT INTO dbmail_subscription (user_id, mailbox_id) 
                                SELECT owner_idnr, mailbox_idnr FROM dbmail_mailboxes WHERE owner_idnr = %d
                                ''' % user_idnr
                               )

            # Assign new user to default mail aliases.
            if len(assignedAliases) > 0:
                for ali in assignedAliases:
                    try:
                        self.conn.update('dbmail_aliases',
                                         where='alias = %s AND deliver_to <> %d' % (web.sqlquote(ali), user_idnr),
                                         deliver_to=web.sqlliteral('CONCAT(%s, ",", deliver_to)' % sqlquoted_mail),
                                        )
                    except:
                        pass

            # Create Amavisd policy for newly created user.
            if settings.AMAVISD_EXECUTE_SQL_WITHOUT_ENABLED and settings.AMAVISD_SQL_FOR_NEWLY_CREATED_USER:
                vars_amavisd = {
                    'mail': sqlquoted_mail,
                    'username': web.sqlquote(self.username),
                    'domain': web.sqlquote(self.domain),
                }
                try:
                    from libs.amavisd.core import AmavisdWrap
                    amwrap = AmavisdWrap()
                    for sql_cmd in settings.AMAVISD_SQL_FOR_NEWLY_CREATED_USER:
                        amwrap.db.query(sql_cmd % vars_amavisd)
                except:
                    pass

            web.logger(msg="Create user: %s." % (self.mail), domain=self.domain, event='create',)
            return (True,)
        except Exception, e:
            return (False, str(e))

    @decorators.require_domain_access
    def update(self, profile_type, mail, data):
        self.profile_type = web.safestr(profile_type)
        self.mail = str(mail).lower()
        self.domain = self.mail.split('@', 1)[-1]

        # Pre-defined update key:value.
        updates = {}

        # Get `dbmail_users.user_idnr`.
        try:
            qr = self.conn.select(
                'dbmail_users',
                where='userid = %s' % web.sqlquote(self.mail),
                what='user_idnr',
                limit=1,
            )
            if qr:
                self.user_idnr = str(qr[0].user_idnr)
            else:
                return (False, 'INVALID_MAIL')
        except Exception, e:
            return (False, str(e))

        if self.profile_type == 'general':
            # Get name
            cn = data.get('cn', '')
            updates['name'] = cn

            # Get mail quota size.
            mailQuota = str(data.get('mailQuota', 0))
            if mailQuota.isdigit():
                updates['maxmail_size'] = int(mailQuota) * 1024 * 1024

            # Get employee id.
            #employeeNumber = data.get('employeeNumber', '')
            #updates['employeeid'] = employeeNumber

            # Get list of assigned alias accounts.
            old_member_of_aliases = [str(addr).lower()
                                     for addr in data.get('oldMemberOfAlias', [])
                                     if iredutils.isEmail(addr) and str(addr).endswith('@' + self.domain)
                                    ]

            # Get list of newly assigned alias accounts.
            member_of_aliases = [str(addr).lower()
                                 for addr in data.get('memberOfAlias', [])
                                 if iredutils.isEmail(addr)
                                 and str(addr).endswith('@'+self.domain)
                                ]

            newly_assigned_aliases = [str(addr).lower() for addr in member_of_aliases if addr not in old_member_of_aliases]
            removed_aliases = [str(addr).lower() for addr in old_member_of_aliases if addr not in member_of_aliases]

            # Remove user from aliases if not in both existing_aliases and new_aliases.
            # Assign user to new aliases.
            if newly_assigned_aliases:
                try:
                    self.conn.update('dbmail_aliases',
                                     where='alias IN %s' % web.sqlquote(newly_assigned_aliases),
                                     deliver_to=web.sqlliteral('CONCAT("%s", ",", deliver_to)' % self.mail),
                                    )
                except:
                    pass

            # Remove user from old assigned aliases.
            if removed_aliases:
                # Get profiles of alias accounts.
                alias_profiles = self.conn.select('dbmail_aliases',
                                                  what='alias,deliver_to',
                                                  where='alias IN %s' % web.sqlquote(removed_aliases),
                                                 )

                for als in alias_profiles:
                    try:
                        als_members = [str(addr).lower() for addr in str(als.deliver).replace(' ', '').split(',') if str(addr).lower() != self.mail ]

                        # Remove current user from alias accounts.
                        self.conn.update('dbmail_aliases',
                                         where='alias = %s' % web.sqlquote(als.alias),
                                         goto=','.join(als_members),
                                        )
                    except:
                        pass

        elif self.profile_type == 'forwarding':
            mailForwardingAddresses = list(set([str(addr).lower()
                                     for addr in data.get('mailForwardingAddresses', '').splitlines()
                                     if iredutils.isEmail(addr)
                                    ]))

            if self.mail in mailForwardingAddresses:
                mailForwardingAddresses.remove(self.mail)

            # Delete record first, then insert again.
            try:
                self.conn.delete('dbmail_aliases', where='alias=%s' % web.sqlquote(self.mail))
            except Exception, e:
                return (False, str(e))

            if len(mailForwardingAddresses) > 0:
                forwarding_addresses_in_domain = [addr for addr in mailForwardingAddresses if addr.endswith('@' + self.domain)]
                forwarding_addresses_not_in_domain = [addr for addr in mailForwardingAddresses if not addr.endswith('@' + self.domain)]

                # Re-generate list of forwarding addresses, remove non-exist mail users in same domain.
                # Get `dbmail_users.user_idnr` of mail users.
                if len(forwarding_addresses_in_domain) > 0:
                    qr = self.conn.select(
                        'dbmail_users',
                        what='userid',
                        where='domain = %s AND %s' % (
                            web.sqlquote(self.domain),
                            web.sqlors('userid = ', forwarding_addresses_in_domain),
                        ),
                    )

                    if qr:
                        forwarding_addresses_in_domain = [str(rcd.userid).lower() for rcd in qr]

                if 'savecopy' in data.keys():
                    forwarding_addresses_in_domain += [self.user_idnr]
            else:
                # Save address=goto to keep catch-all working.
                forwarding_addresses_in_domain = [self.user_idnr]

            if forwarding_addresses_in_domain or forwarding_addresses_not_in_domain:
                sql_values = [{'alias': self.mail, 'deliver_to': addr,}
                               for addr in forwarding_addresses_in_domain + forwarding_addresses_not_in_domain
                              ]
                try:
                    self.conn.multiple_insert('dbmail_aliases', sql_values)
                    return (True,)
                except Exception, e:
                    return (False, str(e))

        elif self.profile_type == 'aliases':
            # Delete record first, then insert again.
            try:
                self.conn.delete('dbmail_aliases', where='deliver_to=%s' % web.sqlquote(self.user_idnr))
            except Exception, e:
                return (False, str(e))

            user_alias_addresses = list(set([str(addr).lower()
                                     for addr in data.get('userAliasAddresses', '').splitlines()
                                     if iredutils.isEmail(addr) and addr.endswith('@' + self.domain)
                                    ]))

            # Make sure submitted addresses are not assigned to other mail users.
            if user_alias_addresses:
                try:
                    qr = self.conn.select(
                        'dbmail_aliases',
                        what='alias',
                        where='%s' % web.sqlors('alias = ', user_alias_addresses),
                    )

                    if qr:
                        exist_addresses = [str(rcd.alias).lower() for rcd in qr]
                        user_alias_addresses = [addr
                                                for addr in user_alias_addresses
                                                if addr not in exist_addresses
                                               ]
                    del qr
                except Exception, e:
                    return (False, str(e))

            user_alias_addresses += [self.mail]

            # Insert new records.
            if user_alias_addresses:
                sql_values = [{'alias': addr, 'deliver_to': self.user_idnr,}
                               for addr in user_alias_addresses
                              ]
                try:
                    self.conn.multiple_insert('dbmail_aliases', sql_values)
                    return (True,)
                except Exception, e:
                    return (False, str(e))
            else:
                return (True,)


        elif self.profile_type == 'bcc':
            # Get bcc status
            rbcc_active = 0
            sbcc_active = 0
            if 'recipientbcc' in data.keys(): rbcc_active = 1
            if 'senderbcc' in data.keys(): sbcc_active = 1

            # Get sender/recipient bcc.
            senderBccAddress = str(data.get('senderBccAddress', ''))
            recipientBccAddress = str(data.get('recipientBccAddress', ''))

            updates_sender_bcc = {}
            updates_recipient_bcc = {}
            if iredutils.isEmail(senderBccAddress):
                updates_sender_bcc = {'username': self.mail,
                                      'bcc_address': senderBccAddress,
                                      'domain': self.domain,
                                      'created': iredutils.sqlNOW,
                                      'active': sbcc_active,
                                     }

            if iredutils.isEmail(recipientBccAddress):
                updates_recipient_bcc = {'username': self.mail,
                                         'bcc_address': recipientBccAddress,
                                         'domain': self.domain,
                                         'created': iredutils.sqlNOW,
                                         'active': rbcc_active,
                                        }

            try:
                # Delete bcc records first.
                self.conn.delete('sender_bcc_user', where='username=%s' % web.sqlquote(self.mail))
                self.conn.delete('recipient_bcc_user', where='username=%s' % web.sqlquote(self.mail))

                # Insert new records.
                if updates_sender_bcc:
                    self.conn.insert('sender_bcc_user', **updates_sender_bcc)

                if updates_recipient_bcc:
                    self.conn.insert('recipient_bcc_user', **updates_recipient_bcc)
            except Exception, e:
                return (False, str(e))

        elif self.profile_type == 'relay':
            # Get transport.
            self.transport = str(data.get('mtaTransport', ''))
            updates['transport'] = self.transport

        elif self.profile_type == 'throttle':
            self.senderThrottlingSetting = throttle.getSenderThrottlingSettingFromForm(
                account=self.mail,
                accountType='user',
                form=data,
            )

            self.recipientThrottlingSetting = throttle.getRecipientThrottlingSettingFromForm(
                account=self.mail,
                accountType='user',
                form=data,
            )

            throttleLib = throttle.Throttle()
            try:
                throttleLib.updateThrottlingSetting(
                    account=self.mail,
                    accountType='sender',
                    setting=self.senderThrottlingSetting,
                )

                throttleLib.updateThrottlingSetting(
                    account=self.mail,
                    accountType='recipient',
                    setting=self.recipientThrottlingSetting,
                )
            except Exception, e:
                pass

        elif self.profile_type == 'password':
            newpw = str(data.get('newpw', ''))
            confirmpw = str(data.get('confirmpw', ''))

            # Verify new passwords.
            qr = iredutils.verifyNewPasswords(newpw, confirmpw)
            if qr[0] is True:
                if 'storePasswordInPlainText' in data:
                    self.passwd = iredutils.getSQLPassword(qr[1], pwscheme='PLAIN')
                else:
                    self.passwd = iredutils.getSQLPassword(qr[1])
            else:
                return qr

            # Hash/encrypt new password.
            updates['passwd'] = self.passwd

        elif self.profile_type == 'advanced':
            # Get enabled services.
            """
            self.enabledService = [str(v).lower()
                                   for v in data.get('enabledService', [])
                                   if v in ENABLED_SERVICES
                                  ]
            self.disabledService = [v for v in ENABLED_SERVICES if v not in self.enabledService]

            # Append 'sieve', 'sievesecured' for dovecot-1.2.
            if 'enablemanagesieve' in self.enabledService:
                self.enabledService += ['enablesieve']
            else:
                self.disabledService += ['enablesieve']

            if 'enablemanagesievesecured' in self.enabledService:
                self.enabledService += ['enablesievesecured']
            else:
                self.disabledService += ['enablesievesecured']

            # Enable/disable services.
            for srv in self.enabledService:
                updates[srv] = 1

            for srv in self.disabledService:
                updates[srv] = 0
            """
            pass

        else:
            return (True,)

        # Update SQL db with columns: maxquota, active.
        try:
            self.conn.update(
                'dbmail_users',
                where='userid=%s' % (web.sqlquote(self.mail)),
                **updates
            )
            return (True,)
        except Exception, e:
            return (False, str(e))


    @decorators.require_domain_access
    def getMailForwardingAddresses(self, domain, mail):
        self.mail = web.safestr(mail)
        self.domain = self.mail.split('@', 1)[-1]
        self.mailForwardingAddresses = []

        if self.domain != domain:
            raise web.seeother('/domains?msg=PERMISSION_DENIED')

        if not self.mail.endswith('@' + self.domain):
            raise web.seeother('/domains?msg=PERMISSION_DENIED')

        try:
            result = self.conn.select(
                'dbmail_aliases',
                where='alias = %s' % web.sqlquote(self.mail),
                what='deliver_to',
            )
            if result:
                self.mailForwardingAddresses = [str(rcd.deliver_to).lower() for rcd in result]

            return (True, self.mailForwardingAddresses)
        except Exception, e:
            return (False, str(e))

    @decorators.require_domain_access
    def getUserAliasAddresses(self, domain, mail):
        self.mail = web.safestr(mail)
        self.domain = self.mail.split('@', 1)[-1]
        self.userAliasAddresses = []

        if self.domain != domain:
            raise web.seeother('/domains?msg=PERMISSION_DENIED')

        if not self.mail.endswith('@' + self.domain):
            raise web.seeother('/domains?msg=PERMISSION_DENIED')

        # Get `dbmail_users.user_idnr`.
        try:
            qr = self.conn.select(
                'dbmail_users',
                where='userid = %s' % web.sqlquote(self.mail),
                what='user_idnr',
                limit=1,
            )
            if qr:
                self.user_idnr = str(qr[0].user_idnr)
            else:
                return (False, 'INVALID_MAIL')
        except Exception, e:
            return (False, str(e))

        try:
            qr = self.conn.select(
                'dbmail_aliases',
                where='deliver_to = %s' % web.sqlquote(self.user_idnr),
                what='alias',
            )
            if qr:
                self.userAliasAddresses = [str(rcd.alias).lower() for rcd in qr]

            return (True, self.userAliasAddresses)
        except Exception, e:
            return (False, str(e))

