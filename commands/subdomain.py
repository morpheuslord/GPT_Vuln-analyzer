import dns.resolver
from rich.progress import track


def sub(target):
    ss = []

    s_array = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'hod', 'butterfly', 'ckp',
               'tele2', 'receiver', 'reality', 'panopto', 't7', 'thot', 'wien', 'uat-online', 'Footer']
    for subd in track(s_array):
        try:
            ip_value = dns.resolver.resolve(f'{subd}.{target}', 'A')
            if ip_value:
                ss.append(f'{subd}.{target}')
                if f"{subd}.{target}" in ss:
                    print(f'{subd}.{target} | Found')
                else:
                    pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except KeyboardInterrupt:
            print('Ended')
            quit()
