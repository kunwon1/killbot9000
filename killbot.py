import sopel.module
from sopel.tools import stderr

import socket
import dns.resolver

dnsResolver = None

def setup(bot):
    global dnsResolver
    dnsResolver = dns.resolver.Resolver()

@sopel.module.commands('helloworld')
def helloworld(bot, trigger):
    bot.say('Hello, world!')

@sopel.module.commands('host')
@sopel.module.priority('low')
@sopel.module.require_admin
@sopel.module.example('.host google.com')
def doManualLookup(bot, trigger):
    if not trigger.sender == bot.config.killbot.control_channel:
        return
    else:
        list = getIPList(trigger.group(2))
        for ip in list:
            bot.reply(ip)


@sopel.module.event('JOIN')
@sopel.module.rule('.*')
@sopel.module.priority('high')
def processJoin(bot, trigger):
    #stderr(type(trigger.host))
    #stderr(trigger.host)
    ips = getIPList(trigger.host)

    for ip in ips:
        bot.msg(bot.config.killbot.control_channel, ip)


def getIPList(hostname):

    #takes a hostname or ip address, returns list containing
    #ip addresses that hostname resolves to, or original ip address
    #always returns a list

    ipList = []

    if hostname.find('/') != -1:
        #this is a cloak, dns lookups don't matter
        return ipList

    if validateIP(hostname) == True:
        ipList.append('%s' % hostname)
        return ipList

    else:
        stderr('resolving %s' % hostname)
        try:
            ipv4 = dnsResolver.query(hostname,'A')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            ipv4 = []
        try:
            ipv6 = dnsResolver.query(hostname,'AAAA')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            ipv6 = []
        for a in ipv4:
            stderr('    resolved A record to %s' % a)
            ipList.append('%s' % a)
        for aaaa in ipv6:
            stderr('    resolved AAAA record to %s' % aaaa)
            ipList.append('%s' % aaaa)
        return ipList

    #for some reason we couldn't find anything
    stderr('getIPList fell through for %s' % hostname)
    return ipList

def validateIP(address):
    return validateIPV4(address) or validateIPV6(address)

def validateIPV4(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False

    return True

def validateIPV6(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:
        stderr("invalid ipv6")
        return False
    return True

