from faraday_plugins.plugins.plugin import PluginJsonFormat
import json

class AmassJsonParser:
    def __init__(self, json_output):
        self.output = self.parse_json(json_output)

    def parse_json(self, json_output):
        output = json.loads(json_output)
        hosts = {}
        already_defined_hosts = []
        for domain in output['domains']:
            for names in domain['names']:
                hostname = names['name']
                for address in names['addresses']:
                    ip = address['ip']
                    if ip in already_defined_hosts:
                        hosts[ip]['hostnames'].append(hostname)
                    else:
                        hosts[ip] = {}
                        hosts[ip]['hostnames'] = [hostname]
                        hosts[ip]['asn'] = address['desc']
                        already_defined_hosts.append(ip)
        return hosts

class AmassPlugin(PluginJsonFormat):
    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "amass"
        self.id = "amass"
        self.name = "Amass"
        self.extension = ".json"
        self.plugin_version = "0.0.1"

    def parseOutputString(self, output, debug=False):
        parser = AmassJsonParser(output)
        for ip in parser.output:
            self.createAndAddHost(ip, hostnames=parser.output[ip]['hostnames'])

def createPlugin(ignore_info=False):
    return AmassPlugin(ignore_info=ignore_info)
