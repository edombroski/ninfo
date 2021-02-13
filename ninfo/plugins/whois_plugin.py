from ninfo import PluginBase
from subprocess import Popen, PIPE

class whois(PluginBase):
    """This plugin returns the output of the whois program for this ip"""

    name =         'whois'
    title =        'whois'
    description =  'whois'
    cache_timeout =   60*60
    types =     ['ip','ip6','hostname']
    local =     False

    def get_info(self, arg):
        try:
            pipe = Popen(["whois", arg], stdout=PIPE)
            output = pipe.communicate()[0]
            status = pipe.returncode

            output = output.decode('ascii','ignore')
            return dict(status=status, output=output)
        except OSError:
            return dict(status="1", output="whois binary not found on system.")

    def render_template(self, output_type, arg, result):
        if not result:
            return ''
        if output_type == 'text':
            return result['output']
        else:
            return '<pre>%s</pre>' % result['output']

plugin_class = whois
