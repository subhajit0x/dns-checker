import requests
import json
import dns.resolver
import dns.exception

def check_dns(domain):
    # define DNS API sources
    api_sources = [('Google DNS', 'https://dns.google/resolve'), ('Cloudflare DNS', 'https://cloudflare-dns.com/dns-query'), ('1.1.1.1', 'https://1.1.1.1/dns-query')]
    # initialize lists to store results from each API source
    spf_results = []
    dkim_results = []
    dmarc_results = []

    # check SPF record using each API source
    for api_source in api_sources:
        try:
            spf_query = requests.get(api_source[1], params={'name': domain, 'type': 'TXT'}).json()
            spf_record = spf_query['Answer'][0]['data']
            if 'v=spf1' in spf_record:
                spf_results.append((api_source[0], 'valid'))
            else:
                spf_results.append((api_source[0], 'invalid'))
        except:
            spf_results.append((api_source[0], 'error'))

    # check DKIM record using each API source
    for api_source in api_sources:
        try:
            dkim_query = dns.resolver.resolve(f'_adsp._domainkey.{domain}', 'TXT')
            dkim_record = dkim_query[0].strings[0].decode()
            if 'v=DKIM1' in dkim_record:
                dkim_results.append((api_source[0], 'valid'))
            else:
                dkim_results.append((api_source[0], 'invalid'))
        except:
            dkim_results.append((api_source[0], 'error'))

    # check DMARC record using each API source
    for api_source in api_sources:
        try:
            dmarc_query = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            dmarc_record = dmarc_query[0].strings[0].decode()
            if 'v=DMARC1' in dmarc_record and 'p=reject' in dmarc_record:
                dmarc_results.append((api_source[0], 'valid'))
            else:
                dmarc_results.append((api_source[0], 'invalid'))
        except:
            dmarc_results.append((api_source[0], 'error'))

    # print results from each API source
    print(f"SPF record results for {domain}:")
    for result in spf_results:
        print(f" - {result[0]}: {result[1]}")
    print(f"DKIM record results for {domain}:")
    for result in dkim_results:
        print(f" - {result[0]}: {result[1]}")
    print(f"DMARC record results for {domain}:")
    for result in dmarc_results:
        print(f" - {result[0]}: {result[1]}")
    
domain = input('Enter the domain to check: ')
check_dns(domain)
