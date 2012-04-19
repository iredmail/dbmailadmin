# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from libs import iredutils
from libs.dbmail_mysql import decorators, domain as domainlib, admin as adminlib, alias as aliaslib

cfg = web.iredconfig
session = web.config.get('_session')


if session.get('enablePolicyd'):
    from libs.policyd import throttle


#
# Domain related.
#


class List:
    '''List all virtual mail domains.'''
    @decorators.require_login
    def GET(self, cur_page=1,):
        i = web.input()

        cur_page = int(cur_page) or 1

        domainLib = domainlib.Domain()
        result = domainLib.listAccounts(cur_page=cur_page)

        if result[0] is True:
            allDomains = result[2]

            aliasDomains = {}

            # Get list of domain names.
            all_domain_names = [r.domain for r in allDomains]
            qr = domainLib.getAllAliasDomains(all_domain_names, namesOnly=True)
            if qr[0] is True:
                aliasDomains = qr[1]

            return web.render(
                'dbmail_mysql/domain/list.html',
                cur_page=cur_page,
                total=result[1],
                allDomains=result[2],
                aliasDomains=aliasDomains,
                msg=i.get('msg', None),
            )
        else:
            return web.render(
                'dbmail_mysql/domain/list.html',
                cur_page=cur_page,
                total=0,
                allDomains=[],
                msg=result[1],
            )

    @decorators.require_global_admin
    @decorators.csrf_protected
    @decorators.require_login
    def POST(self):
        i = web.input(domainName=[], _unicode=False,)
        domainName = i.get('domainName', None)
        self.action = i.get('action')

        domainLib = domainlib.Domain()
        if self.action == 'delete':
            result = domainLib.delete(domains=domainName)
            msg = 'DELETED'
        elif self.action == 'disable':
            result = domainLib.enableOrDisableAccount(accounts=domainName, active=False,)
            msg = 'DISABLED'
        elif self.action == 'enable':
            result = domainLib.enableOrDisableAccount(accounts=domainName, active=True,)
            msg = 'ENABLED'
        else:
            result = (False, 'INVALID_ACTION')
            msg = i.get('msg', None)

        if result[0] is True:
            raise web.seeother('/domains?msg=%s' % msg)
        else:
            raise web.seeother('/domains?msg=' + web.urlquote(result[1]))


class Profile:
    @decorators.require_login
    def GET(self, profile_type, domain):
        i = web.input()
        self.domain = web.safestr(domain.split('/', 1)[0])
        self.profile_type = web.safestr(profile_type)

        domainLib = domainlib.Domain()
        result = domainLib.profile(domain=self.domain)

        if result[0] is not True:
            raise web.seeother('/domains?msg=' + web.urlquote(result[1]))
        else:
            self.profile = result[1]

        allAdmins = []      # Get all admins.
        domainAdmins = []   # Get domain admins.
        aliasDomains = []   # Get all alias domains.
        allAliases = []     # Get all mail aliases.
        # profile_type == 'throttle'
        throttleOfSender = {}
        throttleOfRecipient = {}

        adminLib = adminlib.Admin()
        # Get all admins.
        qr = adminLib.getAllAdmins(columns=['username', 'name'])
        if qr[0] is True:
            allAdmins = qr[1]

        # Get domain admins.
        qr = domainLib.getDomainAdmins(domain=self.domain, mailOnly=True)
        if qr[0] is True:
            domainAdmins = qr[1]

        # Get alias domains.
        qr = domainLib.getAllAliasDomains(self.domain, namesOnly=True,)
        if qr[0] is True:
            aliasDomains = qr[1]

        # Get all mail aliases.
        mailsOfAllAliases = []
        aliasLib = aliaslib.Alias()
        qr = aliasLib.getAllAliases(domain=self.domain, columns=['name', 'alias', ])
        if qr[0] is True:
            allAliases = qr[1]
            for ali in allAliases:
                mailsOfAllAliases += [ali.alias]

        # Get sender/recipient throttle data from policyd database.
        if session.get('enablePolicyd'):
            throttleLib = throttle.Throttle()
            result_throttle = throttleLib.getThrottling(sender='@' + self.domain, recipient='@' + self.domain)
            if result_throttle[0] is True:
                throttleOfSender = result_throttle[1]
                throttleOfRecipient = result_throttle[2]

        return web.render(
            'dbmail_mysql/domain/profile.html',
            cur_domain=self.domain,
            profile_type=self.profile_type,
            profile=self.profile,
            allAdmins=allAdmins,
            domainAdmins=domainAdmins,
            aliasDomains=aliasDomains,
            allAliases=allAliases,
            mailsOfAllAliases=mailsOfAllAliases,
            throttleOfSender=throttleOfSender,
            throttleOfRecipient=throttleOfRecipient,
            msg=i.get('msg'),
        )

    @decorators.csrf_protected
    @decorators.require_login
    def POST(self, profile_type, domain):
        self.profile_type = str(profile_type)
        self.domain = str(domain)

        i = web.input(domainAliasName=[], domainAdmin=[], defaultList=[],)

        domainLib = domainlib.Domain()
        result = domainLib.update(
            profile_type=self.profile_type,
            domain=self.domain,
            data=i,
        )

        if result[0] is True:
            raise web.seeother('/profile/domain/%s/%s?msg=UPDATED' % (self.profile_type, self.domain))
        else:
            raise web.seeother('/profile/domain/%s/%s?msg=%s' % (self.profile_type, self.domain, web.urlquote(result[1]),))


class Create:
    @decorators.require_global_admin
    @decorators.require_login
    def GET(self):
        i = web.input()
        return web.render(
            'dbmail_mysql/domain/create.html',
            msg=i.get('msg'),
        )

    @decorators.require_global_admin
    @decorators.csrf_protected
    @decorators.require_login
    def POST(self):
        i = web.input()
        self.domain = web.safestr(i.get('domainName')).strip().lower()
        domainLib = domainlib.Domain()
        result = domainLib.add(data=i)
        if result[0] is True:
            raise web.seeother('/profile/domain/general/%s?msg=CREATED' % self.domain)
        else:
            raise web.seeother('/create/domain?msg=%s' % web.urlquote(result[1]))
