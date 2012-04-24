# encoding: utf-8

# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from libs import iredutils
from libs.dbmail_mysql import decorators, user as userlib, domain as domainlib, alias as aliaslib, connUtils

cfg = web.iredconfig
session = web.config.get('_session')

if session.get('enablePolicyd'):
    from libs.policyd import throttle


class List:
    @decorators.require_login
    def GET(self, domain, cur_page=1):
        self.domain = web.safestr(domain).split('/', 1)[0]
        cur_page = int(cur_page) or 1

        userLib = userlib.User()
        result = userLib.listAccounts(domain=self.domain, cur_page=cur_page,)
        if result[0] is True:
            (total, records) = (result[1], result[2])

            return web.render(
                'dbmail_mysql/user/list.html',
                cur_domain=self.domain,
                cur_page=cur_page,
                total=total,
                users=records,
                msg=web.input().get('msg', None),
            )
        else:
            raise web.seeother('/domains?msg=%s' % web.urlquote(result[1]))

    @decorators.csrf_protected
    @decorators.require_login
    def POST(self, domain):
        i = web.input(_unicode=False, mail=[])
        self.domain = web.safestr(domain)

        self.mails = [str(v)
                      for v in i.get('mail', [])
                      if iredutils.isEmail(v)
                      and str(v).endswith('@' + self.domain)
                     ]

        self.action = i.get('action', None)
        msg = i.get('msg', None)

        userLib = userlib.User()

        if self.action == 'delete':
            result = userLib.delete(domain=self.domain, mails=self.mails,)
            msg = 'DELETED'
        elif self.action == 'disable':
            result = userLib.enableOrDisableAccount(domain=self.domain, accounts=self.mails, active=False,)
            msg = 'DISABLED'
        elif self.action == 'enable':
            result = userLib.enableOrDisableAccount(domain=self.domain, accounts=self.mails, active=True,)
            msg = 'ENABLED'
        else:
            result = (False, 'INVALID_ACTION')

        if result[0] is True:
            raise web.seeother('/users/%s?msg=%s' % (self.domain, msg,))
        else:
            raise web.seeother('/users/%s?msg=%s' % (self.domain, web.urlquote(result[1]),))


class Profile:
    @decorators.require_login
    def GET(self, profile_type, mail):
        i = web.input()
        self.mail = str(mail).lower()
        self.cur_domain = self.mail.split('@', 1)[-1]
        self.profile_type = str(profile_type)

        # profile_type == 'throttle'
        throttleOfSender = {}
        throttleOfRecipient = {}

        if self.mail.startswith('@') and iredutils.isDomain(self.cur_domain):
            # Catchall account.
            raise web.seeother('/profile/domain/catchall/%s' % (self.cur_domain))

        if not iredutils.isEmail(self.mail):
            raise web.seeother('/domains?msg=INVALID_USER')

        if not iredutils.isDomain(self.cur_domain):
            raise web.seeother('/domains?msg=INVALID_DOMAIN_NAME')

        userLib = userlib.User()
        qr = userLib.profile(domain=self.cur_domain, mail=self.mail)
        if qr[0] is True:
            self.profile = qr[1]
        else:
            raise web.seeother('/users/%s?msg=%s' % (self.cur_domain, web.urlquote(qr[1])))
        del qr

        # Get mail alias addresses.
        qr = userLib.getUserAliasAddresses(domain=self.cur_domain, mail=self.mail)
        if qr[0] is True:
            self.userAliasAddresses = qr[1]
        else:
            raise web.seeother('/users/%s?msg=%s' % (self.cur_domain, web.urlquote(qr[1])))
        del qr

        # Get mail forwarding addresses.
        qr = userLib.getMailForwardingAddresses(domain=self.cur_domain, mail=self.mail)
        if qr[0] is True:
            self.mailForwardingAddresses = qr[1]
        else:
            raise web.seeother('/users/%s?msg=%s' % (self.cur_domain, web.urlquote(qr[1])))
        del qr

        # Get all aliases under same domain.
        allAliases = []
        aliasLib = aliaslib.Alias()
        qr = aliasLib.getAllAliases(domain=self.cur_domain, columns=['name', 'alias', 'deliver_to'])
        if qr[0] is True:
            allAliases = qr[1]

        if session.get('enablePolicyd'):
            # Get sender/recipient throttle data from policyd database.
            throttleLib = throttle.Throttle()
            result_throttle = throttleLib.getThrottling(sender=self.mail, recipient=self.mail)
            if result_throttle[0] is True:
                throttleOfSender = result_throttle[1]
                throttleOfRecipient = result_throttle[2]

        return web.render(
            'dbmail_mysql/user/profile.html',
            cur_domain=self.cur_domain,
            mail=self.mail,
            profile_type=self.profile_type,
            profile=self.profile,
            userAliasAddresses=self.userAliasAddresses,
            mailForwardingAddresses=self.mailForwardingAddresses,
            allAliases=allAliases,
            throttleOfSender=throttleOfSender,
            throttleOfRecipient=throttleOfRecipient,
            msg=i.get('msg'),
        )

    @decorators.csrf_protected
    @decorators.require_login
    def POST(self, profile_type, mail):
        i = web.input(
            enabledService=[],
            #mailForwardingAddress=[],
            shadowAddress=[],
            telephoneNumber=[],
            memberOfGroup=[],
            oldMemberOfAlias=[],
            memberOfAlias=[],
            #whitelistSender=[],
            #blacklistSender=[],
            #whitelistRecipient=[],
            #blacklistRecipient=[],
        )
        self.profile_type = web.safestr(profile_type)
        self.mail = str(mail).lower()

        userLib = userlib.User()
        result = userLib.update(
            profile_type=self.profile_type,
            mail=self.mail,
            data=i,
        )

        if result[0] is True:
            raise web.seeother('/profile/user/%s/%s?msg=UPDATED' % (self.profile_type, self.mail))
        else:
            raise web.seeother('/profile/user/%s/%s?msg=%s' % (self.profile_type, self.mail, web.urlquote(result[1])))


class Create:
    @decorators.require_login
    def GET(self, domain=None,):
        if domain is None:
            self.cur_domain = None
        else:
            self.cur_domain = str(domain)
            if not iredutils.isDomain(self.cur_domain):
                raise web.seeother('/domains?msg=INVALID_DOMAIN_NAME')

        i = web.input()

        # Get all managed domains.
        connutils = connUtils.Utils()
        qr = connutils.getManagedDomains(admin=session.get('username'), domainNameOnly=True,)

        if qr[0] is True:
            allDomains = qr[1]
        else:
            raise web.seeother('/domains?msg=' + web.urlquote(qr[1]))

        # Set first domain as current domain.
        if self.cur_domain is None:
            if len(allDomains) > 0:
                raise web.seeother('/create/user/%s' % str(allDomains[0]))
            else:
                raise web.seeother('/domains?msg=NO_DOMAIN_AVAILABLE')

        # Get domain profile.
        domainLib = domainlib.Domain()
        resultOfProfile = domainLib.profile(domain=self.cur_domain)
        if resultOfProfile[0] is True:
            self.profile = resultOfProfile[1]
        else:
            raise web.seeother('/domains?msg=%s' % web.urlquote(resultOfProfile[1]))

        # Cet total number and allocated quota size of existing users under domain.
        self.numberOfExistAccounts = 0
        self.usedQuotaSize = 0

        qr = domainLib.getCountsOfExistAccountsUnderDomain(
            domain=self.cur_domain,
            accountType='user',
        )
        if qr[0] is True:
            self.numberOfExistAccounts = qr[1]
            self.usedQuotaSize = qr[2]

        return web.render(
            'dbmail_mysql/user/create.html',
            cur_domain=self.cur_domain,
            allDomains=allDomains,
            profile=self.profile,
            numberOfExistAccounts=self.numberOfExistAccounts,
            usedQuotaSize=self.usedQuotaSize,
            msg=i.get('msg'),
        )

    @decorators.csrf_protected
    @decorators.require_login
    def POST(self, domain):
        i = web.input()

        # Get domain name, username, cn.
        self.username = web.safestr(i.get('username', ''))
        self.cur_domain = web.safestr(i.get('domainName', ''))

        userLib = userlib.User()
        result = userLib.add(domain=self.cur_domain, data=i)
        if result[0] is True:
            raise web.seeother('/profile/user/general/%s@%s?msg=CREATED' % (self.username, self.cur_domain))
        else:
            raise web.seeother('/create/user/%s?msg=%s' % (self.cur_domain, web.urlquote(result[1])))
