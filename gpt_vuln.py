import nmap
import openai
import argparse
import dns.resolver

openai.api_key = "__API__KEY__"
model_engine = "text-davinci-003"
nm = nmap.PortScanner()

parser = argparse.ArgumentParser(
    description='Python-Nmap and chatGPT intigrated Vulnerability scanner')
parser.add_argument('--target', metavar='target', type=str,
                    help='Target IP or hostname')
parser.add_argument('--profile', metavar='profile', type=int, default=1,
                    help='Enter Profile of scan 1-5 (Default: 1)', required=False)
parser.add_argument('--attack', metavar='attack', type=str,
                    help='''
                    Enter Attack type nmap, dns or sub. 
                    sub - Subdomain Enumeration using the default array. 
                    dns - to perform DNS Enumeration and get openion from Chat-GPT
                    ''', required=False)
args = parser.parse_args()

target = args.target
profile = args.profile
attack = args.attack


def banner():
    print("""
 _______ _     _ _______ 
(_______|_)   (_|_______)
 _   ___ _     _ _______ 
| | (_  | |   | |  ___  |
| |___) |\ \ / /| |   | |
 \_____/  \___/ |_|   |_|
                                                      
    """)


def p1(ip):
    nm.scan('{}'.format(ip), arguments='-Pn -sV -T4 -O -F')
    json_data = nm.analyse_nmap_xml_scan()
    analize = json_data["scan"]
    try:
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return response


def p2(ip):
    nm.scan('{}'.format(ip), arguments='-Pn -T4 -A -v')
    json_data = nm.analyse_nmap_xml_scan()
    analize = json_data["scan"]
    try:
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return response


def p3(ip):
    nm.scan('{}'.format(ip), arguments='-Pn -sS -sU -T4 -A -v')
    json_data = nm.analyse_nmap_xml_scan()
    analize = json_data["scan"]
    try:
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return response


def p4(ip):
    nm.scan('{}'.format(ip), arguments='-Pn -p- -T4 -A -v')
    json_data = nm.analyse_nmap_xml_scan()
    analize = json_data["scan"]
    try:
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return response


def p5(ip):
    nm.scan('{}'.format(
        ip), arguments='-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln')
    json_data = nm.analyse_nmap_xml_scan()
    analize = json_data["scan"]
    try:
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return response


def dnsr(target):
    analize = ''
    record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'TXT']
    for records in record_types:
        try:
            answer = dns.resolver.resolve(target, records)
            for server in answer:
                st = server.to_text()
                analize += "\n"
                analize += records
                analize += " : "
                analize += st
        except dns.resolver.NoAnswer:
            print('No record Found')
            pass
        except KeyboardInterrupt:
            print("Bye")
            quit()
    try:
        prompt = "do a DNS analysis of {} and return proper clues for an attack in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return response


def sub(target):
    s_array = ['www','mail','ftp','localhost','webmail','smtp','pop','ns1','webdisk','ns2','cpanel','whm','autodiscover','autoconfig','m','imap','test','ns','blog','pop3','dev','www2','admin','forum','news','vpn','ns3','mail2','new','mysql','old','lists','support','mobile','mx','static','docs','beta','shop','sql','secure','demo','cp','calendar','wiki','web','media','email','images','img','www1','intranet','portal','video','sip','dns2','api','cdn','stats','dns1','ns4','www3','dns','search','staging','server','mx1','chat','wap','my','svn','mail1','sites','proxy','ads','host','crm','cms','backup','mx2','lyncdiscover','info','apps','download','remote','db','forums','store','relay','files','newsletter','app','live','owa','en','start','sms','office','exchange','ipv4','mail3','help','blogs','helpdesk','web1','home','library','ftp2','ntp','monitor','login','service','correo','www4','moodle','it','gateway','gw','i','stat','stage','ldap','tv','ssl','web2','ns5','upload','nagios','smtp2','online','ad','survey','data','radio','extranet','test2','mssql','dns3','jobs','services','panel','irc','hosting','cloud','de','gmail','s','bbs','cs','ww','mrtg','git','image','members','poczta','s1','meet','preview','fr','cloudflare-resolve-to','dev2','photo','jabber','legacy','go','es','ssh','redmine','partner','vps','server1','sv','ns6','webmail2','av','community','cacti','time','sftp','lib','facebook','www5','smtp1','feeds','w','games','ts','alumni','dl','s2','phpmyadmin','archive','cn','tools','stream','projects','elearning','im','iphone','control','voip','test1','ws','rss','sp','wwww','vpn2','jira','list','connect','gallery','billing','mailer','update','pda','game','ns0','testing','sandbox','job','events','dialin','ml','fb','videos','music','a','partners','mailhost','downloads','reports','ca','router','speedtest','local','training','edu','bugs','manage','s3','status','host2','ww2','marketing','conference','content','network-ip','broadcast-ip','english','catalog','msoid','mailadmin','pay','access','streaming','project','t','sso','alpha','photos','staff','e','auth','v2','web5','web3','mail4','devel','post','us','images2','master','rt','ftp1','qa','wp','dns4','www6','ru','student','w3','citrix','trac','doc','img2','css','mx3','adm','web4','hr','mailserver','travel','sharepoint','sport','member','bb','agenda','link','server2','vod','uk','fw','promo','vip','noc','design','temp','gate','ns7','file','ms','map','cache','painel','js','event','mailing','db1','c','auto','img1','vpn1','business','mirror','share','cdn2','site','maps','tickets','tracker','domains','club','images1','zimbra','cvs','b2b','oa','intra','zabbix','ns8','assets','main','spam','lms','social','faq','feedback','loopback','groups','m2','cas','loghost','xml','nl','research','art','munin','dev1','gis','sales','images3','report','google','idp','cisco','careers','seo','dc','lab','d','firewall','fs','eng','ann','mail01','mantis','v','affiliates','webconf','track','ticket','pm','db2','b','clients','tech','erp','monitoring','cdn1','images4','payment','origin','client','foto','domain','pt','pma','directory','cc','public','finance','ns11','test3','wordpress','corp','sslvpn','cal','mailman','book','ip','zeus','ns10','hermes','storage','free','static1','pbx','banner','mobil','kb','mail5','direct','ipfixe','wifi','development','board','ns01','st','reviews','radius','pro','atlas','links','in','oldmail','register','s4','images6','static2','id','shopping','drupal','analytics','m1','images5','images7','img3','mx01','www7','redirect','sitebuilder','smtp3','adserver','net','user','forms','outlook','press','vc','health','work','mb','mm','f','pgsql','jp','sports','preprod','g','p','mdm','ar','lync','market','dbadmin','barracuda','affiliate','mars','users','images8','biblioteca','mc','ns12','math','ntp1','web01','software','pr','jupiter','labs','linux','sc','love','vcma','webster','staging40','regulus','sztz','brutus','strony','f6','fn','kgb','s142','s148','syndication','pri','techhelp','iklan','vcp','vc3','cio','thanhtra','webprod','bogota','rst','cmdb','public2','public1','zbx','archive1','vtc','www-uat','radios','websurvey','srvc78','azmoon','web101','zim','webdev2','webcall','gsl','dap','astronomy','zakon','bps','wallace','styles','taz','tan','fiona','timesheets','ira','olympus','studsovet','tolyatti','srv14','alma','wikidev','fukushima','ns105','haiti','ftpadmin','kraken','blog3','veterans','e5','asr','ru1','pes','pen','userweb','xchange','livecam','nfsen','patrimonio','u3','un','sanjose','keywords','persephone','crucible','inspire','megaplan','gesundheit','imgweb','sii','sin','ns70','edm2','cbi','desa','mailmems','presta','bobae','cims','media6','webhost1','fortress','spamwall','s66','customercare','libopac','administrator','emeeting','mbm','mbt','ama','lip','gest','amway','pca','pc3','gitweb','usability','img07','great','funny','animal','besyo','archer','cher','op2','dec','dakar','vserver','teo','ns2a','obits','gss','aday','host19','t8','lp3','static8','smsgw','kat','kaz','newftp','mydev','yukon','patches','uno','musique','36','vmware2','d10','d12','telefonia','mdc','droid','primo','mali','cust','nancy','ssm','olap','bars','pav','paf','handbook','motion','obit','server45','server46','server40','centre','ernie','petra','concorde','pooh','wmt','wm2','osm','cs16','politik','movie1','beeline','dimdim','cdp1','konto','finger','florence','smtp-relay','mamba','qms','optima','tableau','solarwinds','wwu','drupal7','dpt','dpa','up1','correos','windows2','rubicon','field','json','material','opus','mx-1','sodium','nfc','fld','beaver','stwww','roberto','bsmtp','banana','golestan','nightly','johnson','blogue','jszx','oid','oic','blackbird','fang','virt1','sems','fiesta','ngo','cdl','bdd','pics2','tims','flv2','ap01','wcg','ots','ott','yjszs','kemahasiswaan','ident','ssg','kilo','ichat','project1','statystyki','america','stark','apollo2','dlib','pace','mssql5','basis','utv','streaming1','sfl','s78','cloud4','skype','addon','sitetest','b9','bx','openmeetings','oob','msu','msb','bf2','bigsavings','r4','dsa','img08','godzilla','stream5','oakland','jesse','host16','eac','bsh','aplus','origin-live','save-big','cats','dmail','sergey','sd3','bulten','nba','fiber','fip','bigsave','pivot','nora','echo360','relay5','jxzy','belize','infosys','host50','080','adminmail','moodle-dev','wonder','vh1','kamery','mum','mun','apartment','travaux','wisdom','moviegalls2','moviegalls3','moviegalls1','moviegalls4','moviegalls5','archi','rfid','img22','aj','a8','documenti','apus','portuguese','host35','host37','vasco','bux','protect','rate','qw','zpush','betatest','xhtml','lgb','lab1','oskol','base2','echarge','securelab','uzem','sbl','inscripciones','module','redhat','neworleans','sirio','eyny','aton','aga','ags','studentaffairs','dnsmaster','noname','balance','hdd','chameleon','tennessee','omaha','fritz','inkubator','jas','wed','pnc','null','bangladesh','orbit','achieve','bookit','minisites','awc','hpc-oslo-gw','muzeum','gx4','jjxy','www99','apns','drmail','epm','gx3','rooms','mailgate3','providers','collector','amigos','monroe','bialystok','dop','fe1','andromede','square','raphael','aai','megatron','brahms','lookup','rejestracja','pantera','paraguay','vdr','hitech','mid','controle','ulan-ude','loadtest','shuzai','polling','ldaps','ldap4','atl','webplus','loan','ipkvm','matlab','pla','https','prospero','ebanking','sonoivu','webmail-old','hp1','srvc82','srvc87','storefront','csl','teleservices','85st','kodeks','demo17','loto','fr1','czech','s80','s82','s84','s85','s89','sql6','timer','rcc','elsa','olddev','serwer','programy','hermes2','ds01','nhs','arlington','fgc','mg2','april','lps','aspen','innovacion','acd','d11','pano','jxpt','nat-pool','gundam','edition','merkury','ftp13','ftp16','parker','obchod','verona','goofy','wahlen','oj','icdenetim','av1','md1','jee','ppp1','eic','cameron','fourier','diaspora','qa3','defender','fotki','wts','chelny','axel','asistencia','voices','kielce','textile','netherlands','exclusive','metropolis','fao','attendance','s157','s156','sip3','lyncwebconf','tuning','r1soft','ozzy','webedit','relief','apd','cms-test','grafik','flint','srvc42','srvc43','srvc48','ironmail','hannibal','shib','pti','recycling','ankara','n6','server39','publicitate','tci','amigo','minside','arquitectura','martinique','awverify','evm','dbm','cmail','iran','arsenal','ip6','jefferson','fisica','caronte','sonic2','web-dev','malta','accelerator','moses','angola','concord','centreon','ns110','ns113','ns114','extweb','tandem','modem','hls','sensor','vodka','server47','mol','talos','hobbes','ebony','appraisal','168','jin','off','eme','kursy','srvc68','srvc62','srvc63','srvc67','arhiva','abcd','pleiades','hilton','prospect','endeavor','ex1','exc','exo','patent','keeper','kunde','front3','endor','isi','stor','sp-test','ups2','god','mongoose','terminus','lobster','wtest','asterisk2','gabinetevirtual','isms','ultima','ma1','xmlfeed','brisbane','alc','scom','rtg','tarif','remax','viruswall','scribe','pdd','ctp','odn','greenfox','izmir','qk','owa1','pre-www','srvc02','srvc07','srvc08','kolkata','masters','globe','contactus','blago','dias','ogrencikonseyi','kabinet','rise','gogo','lineage2','intro','gdansk','dfs','xian','lana','hosting01','cvsweb','ipade','kdc1','sv8','sv7','svi','thebe','esupport','mobiel','2for1gift','s79','s73','s72','s75','luxembourg','ftpmini','ipsi','umc','umi','cybozu','netops','murray','test99','peanut','ipl-m','ipl-a','wish','test-admin','ani','mysql05','mobileiron','event2','perfil','fb-canvas','hentai','pbi','tomas','leasing','sharefile','guadeloupe','srvc27','srvc22','srvc23','srvc28','horoskop','bcn','bck','egloo','monica','suspended','help2','speedtest4','kantoor','greendog','panasonic','www-4','poste','ddm','comms','w3cache','tdb','certificates','official','covers','sniper','verizon','hi-tech','graal','ibk','bazaar','core4','wwwa','competitions','imgc','imgb','imga','imgt','mistral','mammoth','eniac','hardy','clustermail','vm6','rad2','employees','goose','redmine2','mp7','mp5','mpg','server52','server55','cgc','cgp','be2','kernel','alfred','venture','student1','k3','renshi','mars2','rei','m14','m19','smtp06','granite','srvc73','srvc77','elec','wbt','logan','k1','itsm','biurokarier','tree','stefan','pdu2','tjj','sotttt','sra','imperial','ent1','profi','wotan','svr1','dws','iceman','magnitogorsk','crime','viewer','renwen','video-m','lulu','mx21','hts','voltage-pp-0000','mgt','gerrit','aulas','lyj','studios','sftp2','planner','cont','sail','blink','mrs','heron','cef','cea','cer','crimson','westchester','lucifer','zombie','our','bulksms','st01','registrasi','spielwiese','buzon','chiba','bpc','bpi','spam02','120','129','zh-cn','jo','tromso-gw2','winupdate','aip','lb3','lmc','openemm','togo','sv10','sge','real1','only','aspera','vps15','z3','h10','h14','travail','adc','plataforma','miki','200','ola','ole','nieuw','ns06','nikita','nieruchomosci','ntt','ntv','mtu','mtn','mtm','mtb','cct','cco','asap','rencontres','mail250','duma','fond','ebe','ssl3','ssl4','dn2','smsgate','analog','astrahan','rews','contato','br2','br1','antalya','cns2','indy','void','win22','win24','ger','spica','dieta','apc4','homologa','hj','imaging','enlaces','webm','colombo','webdoc','allianz','deluxe','dwb','emo','gladiator','themis','garnet','jud','tede','srvc92','tenlcdn','telechargement','aloha','banco','mvs','ca1','cau','main2','yh','wwwalt','formularios','interscan','gonzo','webopac','edoas','wds','host26','host23','kariera','download4','abit','edp','81','86','85','project2','tuna','ctd','test23','wsn','version2','icms','cashier','prikol','sco','sc1','comcast','rogue','srvc97','outils','mag1','mage','printshop','senegal','fair','vps14','vps13','hcc','sovet','filip','esx5','claims','col','maild','hmp','bolivia','bugz','sfr','email3','mais','marconi','engelsiz','inicio','pmd','pmg','fanshop','s225','s227','s226','s220','bronx','dns14','dns13','srvc93','srvc98','res1','crt','dppd','tra','heimdall','xe','xq','dewey','smpt','fs5','fsp','origen','videos2','networks','localmail','73','78','bannerweb','itl','itd','edu3','static-m','fdm','mprod','nowe','gate3','atlant','routing','rogers','comments','host18','domen','smithers','cmr','imageserver','challenger','clark','northwest','aud','voip3','colossus','cp4','s06','sxy','gy','espresso','poetry','laposte','wws','wwa','alpha1','www40','www42','nono','nagasaki','pinnacle','emis','backlinks','sok','som','sou','mssql7','hukum','site4','site5','site3','iva','sprint','slim','ds10','digitalmedia','mach','studmail','kip','bgs','ura','cabal','pablo','vae','hod','butterfly','ckp','tele2','receiver','reality','panopto','awp','aikido','solomon','cmsadmin','olympics','222','boulder','stadtplan','subscription','c13','c12','sv02','niu','kansascity','record','srvc53','srvc52','srvc57','srvc58','arrow','outage','syktyvkar','proje','avis','dce','kraft','xxb','acad','firebird','vlab','sweet','arsip','ipn','ipt','ip5','uh','www-admin','fedex','srvc83','strong','fy','vertigo','hef-router','lug','points','hummer','s140','s141','s143','s144','zelda','prx','soluciones','hml','torun','ldapmaster','vf','net1','eblast','kzn','barbara','rse','domaincontrol','pgu','pgs','oa1','skidki','submitimages','testwiki','h24','srvc72','my3','enformatik','chat-service2','benz','resim','aaa2','weixin','gsc','gsb','gsd','gsk','drac','valhalla','ns202','anthropology','dal','day','lists2','traktor','harris','85cc','colaboracion','skt','ragnarok','l4d','corvus','findnsave','leela','nhce','iktisat','srv16','dchub','joshua','acta','dayton','ns104','ppl','newhampshire','nico','blog-dev','th-core','adnet','dangan','kairos','usosweb','91','carrefour','asf','linux11','bancuri','4x4','siap','serv2','srvc18','srvc17','srvc13','srvc12','srvc47','bluesky','bappeda','wuhan','uo','ue','race','holmes','metc','impulse','ngwnameserver2','warrior','nuxeo','hoth','srvc88','lama','carmen','six','temple','ydb','cbh','s69','s67','suse','ccnet','fbdev','aplicativos','s194','innov','lecture','stream02','screenshot','cumulus','bellatrix','uploader','optimum','v12','live3','clean','srvc03','rakuten','tvguide','pct','pcm','pc5','forschung','master2','matematik','pgsql1','cyan','mta6','srvc37','srvc32','srvc38','village','spor','zdrowie','aire','d9','gwmobile','opc','den','stiri','manage2','francais','unreal','bubbles','giveaway','swa','orion2','esmtp','220','testlab','t7','thot','wien','uat-online','Footer']
    
    ss = []
    
    for subd in s_array:
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
    

def main(target):
    banner()
    try:
        if attack == 'nmap':
            match profile:
                case 1:
                    final = p1(target)
                    print(final)
                case 2:
                    final = p2(target)
                    print(final)
                case 3:
                    final = p3(target)
                    print(final)
                case 4:
                    final = p4(target)
                    print(final)
                case 5:
                    final = p5(target)
                    print(final)
        elif attack == 'dns':
            final = dnsr(target)
            print(final)
        elif attack == 'sub':
            final = sub(target)
            print(final)
        else:
            print("Choose a Valid Option")
    except KeyboardInterrupt:
        print("Bye")
        quit()


if __name__ == "__main__":
    main(target)
