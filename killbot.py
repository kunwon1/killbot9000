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

@sopel.module.event('JOIN')
@sopel.module.rule('.*')
@sopel.module.priority('high')
def process_join(bot, trigger):
    #stderr(type(trigger.host))
    #stderr(trigger.host)
    iplist = []
    if trigger.host.find('/') != -1:
        #this is a cloak, dns lookups don't matter
        return
    try:
        socket.inet_aton(trigger.host)
    except socket.error:
        #not a valid IP address, resolve it
        stderr('resolving %s' % trigger.host)
        ipv4 = dnsResolver.query(trigger.host,'A')
        ipv6 = dnsResolver.query(trigger.host,'AAAA')
        for a in ipv4:
            iplist.append('%s' % a)
        for aaaa in ipv6:
            iplist.append('%s' % aaaa)
    else:
        #this is already an ip address, save it
        iplist.append('%s' % trigger.host)

    for ip in iplist:
        bot.msg(bot.config.killbot.control_channel, ip)
