from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader
from django.views import View
import dns.resolver
import re

class DnsView(View):
    #varibles
    report_type = 'report'
    domain_name = ''
    #page titles
    dmarc_title = 'DMARC Record'
    dmarc_title = 'DMARC Record'
    spf_title = 'SPF Record'
    dkim_title = 'DKIM Selectors Found'
    a_title = 'A Record'
    aaaa_title = 'AAAA Record'
    soa_title = 'SOA Record'
    mx_title = 'MX Record'
    ns_title = 'NS Record'
    bimi_title = 'BIMI Record'
    dde_title = 'Double Domain Error'
    txt_title = 'TXT Record'
    #records results
    dmarc_record = ''
    spf_record = ''
    a_record = []
    aaaa_record = []
    soa_record = []
    mx_record = []
    ns_record = []
    bimi_record = ''
    dde_record = ''
    spf_record = ''             # spf record results
    spf_list_all = []
    spf_list = []
    AAAA_LIST = []
    dkim_selectors = ['google', 'selector1', 'selector2', 's1', 's2', 'k1', 'default']
    dkim_list = []
    dmarc_list =[]
    txt_list = []
    rpt_to_dmarcian = []
    no_rpt_to_dmarcian =[]
    A = ['A']
    AAAA = ['AAAA']
    SOA = ['SOA']
    MX = ['MX']
    TXT = ['TXT']
    DKIM = ['TXT']
    NS = ['NS']
    BIMI = 'default._bimi.'

    report_type = ''

    def get(self, response):
        print('GET DNS.HTML')
        return render(response, "dns.html")
        
    def post(self, response):
        page_title_list = {}
        self.domain_name = response.POST['DomainName']
        checkBox = response.POST.getlist('QueryType')
        for check in checkBox:
            if check == 'report':
                self.SearchDmarc(response)
                self.SearchSpf(response)
                self.SearchDkim(response)
                self.SearchA(response)
                self.SearchAAAA(response)
                self.SearchSoa(response)
                self.SearchMx(response)
                self.SearchNs(response)
                self.SearchBimi(response)
                self.SearchDde(response)
                self.report_type = 'report'
                print(self.domain_name)
                return render(response, "dns.html", {
                    'domain_name': self.domain_name,
                    'report_type': self.report_type,
                    'dmarc_list': self.dmarc_list,
                    'rpt_to_dmarcian': self.rpt_to_dmarcian,
                    'no_rpt_to_dmarcian': self.no_rpt_to_dmarcian,
                    'dmarc_title': self.dmarc_title,
                    'dmarc_record': self.dmarc_record,
                    'spf_title': self.spf_title,
                    'spf_list':self.spf_list,
                    'dkim_title': self.dkim_title,
                    'dkim_record': self.dkim_list,
                    'a_title': self.a_title,
                    'a_record': self.a_record,
                    'aaaa_title': self.aaaa_title,
                    'aaaa_record': self.aaaa_record,
                    'soa_title': self.soa_title,
                    'soa_record': self.soa_record,
                    'mx_title': self.mx_title,
                    'mx_record': self.mx_record,
                    'ns_title': self.ns_title,
                    'ns_record': self.ns_record,
                    'bimi_title': self.bimi_title,
                    'bimi_record': self.bimi_record,
                    'dde_title': self.dde_title,
                    'dde_record': self.dde_record
                    })
            else:
                self.report_type = 'individual'
                self.SearchDde(response)
                for check in checkBox:
                    function_list = {'DMARC Record': self.SearchDmarc, 'SPF Record': self.SearchSpf, 'DKIM Selectors': self.SearchDkim, 'A Record': self.SearchA, 'AAAA Record': self.SearchAAAA, 'TXT Record': self.SearchTxt}
                    f = function_list[check]
                    page_title_list[check] = ''
                    f(response)   

                response_list = {'report_type': self.report_type, 'domain_name': self.domain_name, 'rpt_to_dmarcian': self.rpt_to_dmarcian, 'no_rpt_to_dmarcian': self.no_rpt_to_dmarcian, 'DMARC Record': self.dmarc_list, 'spf_list':self.spf_list, 'DKIM Selectors': self.dkim_list, 'A Record': self.a_record, 'AAAA Record': self.aaaa_record, 'TXT Record': self.txt_list}
                for x, z in page_title_list.items():
                    for y, w in response_list.items():
                        if x == y:
                            page_title_list[x] = w

                return render(response, "dns.html", {
                    'page_titles': page_title_list,
                    'domain_name': self.domain_name,
                    'report_type': self.report_type,
                    'dmarc_list': self.dmarc_list,
                    'rpt_to_dmarcian': self.rpt_to_dmarcian,
                    'no_rpt_to_dmarcian': self.no_rpt_to_dmarcian,
                    'dmarc_title': self.dmarc_title,
                    'dmarc_record': self.dmarc_record,
                    'spf_title': self.spf_title,
                    'spf_list':self.spf_list,
                    'dkim_title': self.dkim_title,
                    'dkim_record': self.dkim_list,
                    'a_title': self.a_title,
                    'a_record': self.a_record,
                    'aaaa_title': self.aaaa_title,
                    'aaaa_record': self.aaaa_record,
                    'soa_title': self.soa_title,
                    'soa_record': self.soa_record,
                    'mx_title': self.mx_title,
                    'mx_record': self.mx_record,
                    'ns_title': self.ns_title,
                    'ns_record': self.ns_record,
                    'bimi_title': self.bimi_title,
                    'bimi_record': self.bimi_record,
                    'dde_title': self.dde_title,
                    'dde_record': self.dde_record,
                    'txt_title': self.txt_title,
                    'txt_list': self.txt_list
                    })
    '''
    'report_type': self.report_type,
    
    'soa_title': self.soa_title,
    'mx_title': self.mx_title,
    'ns_title': self.ns_title,
    'soa': self.soa_record,
    'mx': self.mx_record,
    'ns': self.ns_record
    '''
                    
    
    #search DMARC record 
    def SearchDmarc(self, response):
        domainName = response.POST['DomainName']
        self.dmarc_list = []
        self.rpt_to_dmarcian = []
        self.no_rpt_to_dmarcian = []
        dmarc = '_dmarc.' + domainName  # dmarc domain
        for a in self.TXT:
            try:
                answers = dns.resolver.resolve(dmarc, a)
                for rdata in answers:
                    self.dmarc_list.append(rdata.to_text()[1:-1])
                for x in self.dmarc_list:
                    dmarcian_find = x.find('dmarcian')
                    if dmarcian_find > 0:
                        self.rpt_to_dmarcian.append(x)
                    elif dmarcian_find < 0:
                        self.no_rpt_to_dmarcian.append(x)
                    else:
                        pass
            except Exception as e:
                self.dmarc_list = ['None']  
    

    def SearchSpf(self, response):
        domainName = response.POST['DomainName']
        self.spf_list = []
        self.spf_list_all = []
        # search for spf record
        for a in self.TXT:
                try:
                    answers = dns.resolver.resolve(domainName, a)
                    for rdata in answers:
                        self.spf_list_all.append(rdata.to_text())
                    for x in self.spf_list_all:
                        spf_find = re.findall('\A"v=spf1', x)
                        if spf_find:
                            self.spf_list.append(x[1:-1])
                        else:
                            pass
                except Exception as e:
                    self.spf_list = ['None']

    def SearchDkim(self, response):
        domainName = response.POST['DomainName']
        self.dkim_list = []
        for a in self.DKIM:
            for x in self.dkim_selectors:
                try:
                    answers = dns.resolver.resolve(str(f'{x}._domainkey.{domainName}'), a)
                    for rdata in answers:
                        self.dkim_list.append(x +': ' + rdata.to_text())
                except Exception as e:
                    pass
            if self.dkim_list == []:
                self.dkim_list = ['None']                    
            else:
                pass
        
    def SearchA(self, response):
        domainName = response.POST['DomainName']
        self.a_record = []
        for a in self.A:
            try:
                answers = dns.resolver.resolve(domainName, a)
                for rdata in answers:
                    self.a_record.append(rdata.to_text())
            except Exception as e:
                self.a_record = []

    def SearchAAAA(self, response):
        domainName = response.POST['DomainName']
        self.aaaa_record = []
        for a in self.AAAA:
            try:
                answers = dns.resolver.resolve(domainName, a)
                for rdata in answers:
                    self.aaaa_record.append(rdata.to_text())
            except Exception as e:
                self.aaaa_record = []

    def SearchSoa(self, response):
        domainName = response.POST['DomainName']
        self.soa_record = []
        for a in self.SOA:
            try:
                answers = dns.resolver.resolve(domainName, a)
                for rdata in answers:
                    self.soa_record.append(rdata.to_text())
            except Exception as e:
                self.soa_record = []
    
    def SearchMx(self, response):
        domainName = response.POST['DomainName']
        self.mx_record = []
        for a in self.MX:
            try:
                answers = dns.resolver.resolve(domainName, a)
                for rdata in answers:
                    exchange = str(rdata.exchange)
                    preference = str(rdata.preference)
                    self.mx_record.append(str(f'{exchange} {preference}'))                               
            except Exception as e:
                self.mx_record = []

    def SearchNs(self, response):
        domainName = response.POST['DomainName']
        self.ns_record = []
        for a in self.NS:
            try:
                answers = dns.resolver.resolve(domainName, a)
                for rdata in answers:
                    self.ns_record.append(rdata.to_text())
            except Exception as e:
                self.ns_secord = []

    def SearchBimi(self, response):
        domainName = response.POST['DomainName']
        for a in self.TXT:
            try:
                answers = dns.resolver.resolve(str(f'{domainName}{self.BIMI}'), a)
                for rdata in answers:
                    self.bimi_record = rdata.to_text()
            except:
                self.bimi_record = 'None'

    def SearchDde(self, response):
        domainName = response.POST['DomainName']
        self.dde_record = ''
        dde = str(f'_dmarc.{domainName}.{domainName}')
        for a in self.TXT:
            try:
                answers = dns.resolver.resolve(dde, a)
                for rdata in answers:
                    self.dde_record = rdata.to_text()[1:-1]
            except:
                self.dde_record = 'None'

    def SearchTxt(self, response):
        domainName = response.POST['DomainName']
        self.txt_list = []
        for a in self.TXT:
            try:
                answers = dns.resolver.resolve(domainName, a)
                for rdata in answers:
                    self.txt_list.append(rdata.to_text()[1:-1])
            except Exception as e:
                self.txt_list = ['None']
        print(self.txt_list)
def home(request):
    print('homepage')
    template = loader.get_template('home.html')
    return HttpResponse(template.render())  

def article(request):
    print('homepage')
    template = loader.get_template('article.html')
    return HttpResponse(template.render())

