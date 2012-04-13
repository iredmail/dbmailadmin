# encoding: utf-8

# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from libs import iredutils
from libs.dbmail_mysql import decorators, alias as aliaslib, domain as domainlib, connUtils

cfg = web.iredconfig
session = web.config.get('_session')


class List:
    @decorators.require_login
    def GET(self, domain, cur_page=1):
        self.domain = web.safestr(domain)
        cur_page = int(cur_page)

        if not iredutils.isDomain(self.domain):
            raise web.seeother('/domains?msg=INVALID_DOMAIN_NAME')

        if cur_page == 0:
            cur_page = 1

        aliasLib = aliaslib.Alias()
        result = aliasLib.listAccounts(domain=self.domain, cur_page=cur_page,)
        if result[0] is True:
            (total, records) = (result[1], result[2])

            return web.render(
                'dbmail_mysql/alias/list.html',
                cur_domain=self.domain,
                cur_page=cur_page,
                total=total,
                aliases=records,
                msg=web.input().get('msg', None),
            )
        else:
            raise web.seeother('/domains?msg=%s' % web.urlquote(result[1]))

    @decorators.csrf_protected
    @decorators.require_login
    def POST(self, domain):
        i = web.input(_unicode=False, mail=[])

        self.domain = str(domain)
        if not iredutils.isDomain(self.domain):
            raise web.seeother('/domains?msg=INVALID_DOMAIN_NAME')

        self.mails = i.get('mail', [])
        self.action = i.get('action', None)
        msg = i.get('msg', None)

        aliasLib = aliaslib.Alias()

        if self.action == 'delete':
            result = aliasLib.delete(domain=self.domain, mails=self.mails,)
            msg = 'DELETED'
        elif self.action == 'disable':
            result = aliasLib.enableOrDisableAccount(domain=self.domain, accounts=self.mails, active=False,)
            msg = 'DISABLED'
        elif self.action == 'enable':
            result = aliasLib.enableOrDisableAccount(domain=self.domain, accounts=self.mails, active=True,)
            msg = 'ENABLED'
        else:
            result = (False, 'INVALID_ACTION')

        if result[0] is True:
            raise web.seeother('/aliases/%s?msg=%s' % (self.domain, msg,))
        else:
            raise web.seeother('/aliases/%s?msg=%s' % (self.domain, web.urlquote(result[1]),))


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
            raise web.seeother('/domains?msg=' % web.urlquote(qr[1]))

        # Set first domain as current domain.
        if self.cur_domain is None:
            if len(allDomains) > 0:
                raise web.seeother('/create/alias/%s' % str(allDomains[0]))
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

        resultOfCount = domainLib.getCountsOfExistAccountsUnderDomain(
            domain=self.cur_domain,
            accountType='alias',
        )
        if resultOfCount[0] is True:
            self.numberOfExistAccounts = resultOfCount[1]

        return web.render(
            'dbmail_mysql/alias/create.html',
            cur_domain=self.cur_domain,
            allDomains=allDomains,
            profile=self.profile,
            numberOfExistAccounts=self.numberOfExistAccounts,
            numberOfAccounts=2,
            msg=i.get('msg'),
        )

    @decorators.csrf_protected
    @decorators.require_login
    def POST(self, domain):
        i = web.input()

        # Get domain name, username, cn.
        self.cur_domain = web.safestr(i.get('domainName', ''))
        self.username = web.safestr(i.get('listname', ''))
        self.mail = self.username + '@' + self.cur_domain

        if self.cur_domain != domain:
            return (False, 'PERMISSION_DENIED')

        aliasLib = aliaslib.Alias()
        result = aliasLib.add(domain=self.cur_domain, data=i)
        if result[0] is True:
            raise web.seeother('/profile/alias/general/%s?msg=CREATED' % (self.mail))
        else:
            raise web.seeother('/create/alias/%s?msg=%s' % (self.cur_domain, web.urlquote(result[1])))


class Profile:
    @decorators.require_login
    def GET(self, profile_type, mail):
        i = web.input()
        self.mail = web.safestr(mail)
        self.cur_domain = self.mail.split('@', 1)[-1]
        self.profile_type = web.safestr(profile_type)

        if not iredutils.isEmail(self.mail):
            raise web.seeother('/domains?msg=INVALID_USER')

        if not iredutils.isDomain(self.cur_domain):
            raise web.seeother('/domains?msg=INVALID_DOMAIN_NAME')

        aliasLib = aliaslib.Alias()
        qr = aliasLib.profile(domain=self.cur_domain, mail=self.mail)
        if qr[0] is True:
            self.profile = qr[1]
        else:
            raise web.seeother('/aliases/%s?msg=%s' % (self.cur_domain, web.urlquote(qr[1])))

        # Get list of alias members.
        qr = aliasLib.getAliasMembers(mail=self.mail)
        if qr[0] is True:
            members = qr[1]
        else:
            raise web.seeother('/aliases/%s?msg=%s' % (self.cur_domain, web.urlquote(qr[1])))

        return web.render(
            'dbmail_mysql/alias/profile.html',
            cur_domain=self.cur_domain,
            mail=self.mail,
            profile_type=self.profile_type,
            profile=self.profile,
            members=members,
            msg=i.get('msg'),
        )

    @decorators.csrf_protected
    @decorators.require_login
    def POST(self, profile_type, mail):
        self.profile_type = web.safestr(profile_type)
        self.mail = str(mail)
        self.domain = self.mail.split('@', 1)[-1]

        i = web.input(mailForwardingAddress=[], moderators=[],)

        aliasLib = aliaslib.Alias()
        result = aliasLib.update(
            profile_type=self.profile_type,
            mail=self.mail,
            data=i,
        )

        if result[0] is True:
            raise web.seeother('/profile/alias/%s/%s?msg=UPDATED' % (self.profile_type, self.mail,))
        else:
            raise web.seeother('/profile/alias/%s/%s?msg=%s' % (self.profile_type, self.mail, result[1]))
