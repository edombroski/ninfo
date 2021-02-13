from ninfo import PluginBase
import socket
import cymruwhois


class cymru_whois(PluginBase):
    """This plugin returns the owners name and ASN of this host"""

    name = 'cymruwhois'
    title = 'Cymru Whois'
    description = 'Cymru Whois lookup'
    types = ['ip', 'ip6', 'hostname']
    local = False

    def setup(self):
        self.c = cymruwhois.Client()

    def get_info(self, target):
        try:
            ip = socket.gethostbyname(target)
            info = self.c.lookup(ip)
            return info.__dict__
        except socket.gaierror:
            return dict(asn="",cc="",prefix="",owner="Host not found.")

plugin_class = cymru_whois
