from faraday_plugins.plugins.plugin import PluginJsonFormat
import json

class ShodanPlugin(PluginJsonFormat):
    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "shodan"
        self.id = "shodan"
        self.name = "Shodan"
        self.extension = ".json"
        self.plugin_version = "0.0.1"

    def parseOutputString(self, output, debug=False):
        parser = json.loads(output)
        for result in parser:
            description = ""
            if result['data'] is not None:
                description = result['data']
            h_id = self.createAndAddHost(str(result['ip_str']),os=str(result['os']) if result['os'] is not None else "")
            s_id = self.createAndAddServiceToHost(h_id, str(result['product']) if result.__contains__('product') else str(result['port']),
                protocol="tcp",ports=[str(result['port'])],status="open",version=str(result['version']) if result.__contains__('version') else "", description=description)
            if result.__contains__('vulns'):
                for vuln in result['vulns']:
                    self.createAndAddVulnToService(h_id, s_id, vuln, desc=str(result['vulns']['summary']) if result['vulns'].__contains__('summary') else "", resolution=str(result['vulns']["references"]) if result['vulns'].__contains__('references') else "")
def createPlugin(ignore_info=False):
    return ShodanPlugin(ignore_info=ignore_info)
