from GVA import scanner
from GVA import dns_recon
from GVA import subdomain
from GVA import geo
from GVA import gui

openai_key = '__API__KEY__'
geoIP_key = '__API__KEY__'

sub_domain_list = ['admin', 'whateveryouwant']

gui.application()
print(scanner.scanner('127.0.0.1', 1, openai_key))
print(dns_recon.dns_recon('127.0.0.1', openai_key))
print(subdomain.domain('127.0.0.1', sub_domain_list))
print(geo.geo(geoIP_key, '127.0.0.1'))
