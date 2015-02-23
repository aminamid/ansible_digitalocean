#!/usr/bin/python
DOCUMENTATION = '''
'''

EXAMPLES = '''
'''


def recursive_keychk( d, keys ):
    if not keys[0] in d: return None
    return d[keys[0]] if len(keys) == 1 else recursive_keychk( d[keys[0]], keys[1:] )

def req_gen(url, next_key=['links', 'pages', 'next'], **kwargs):
    r = requests.get(url, **kwargs)
    yield r.json()
    while recursive_keychk(r.json(), next_key):
        r = requests.get(url=recursive_keychk(r.json(), next_key), **kwargs)
        yield r.json()
    raise StopIteration

        
    

def main():

    module = AnsibleModule(
      argument_spec = dict(
        method=dict(default='get', choices=['get', 'put', 'post', 'delete', 'header'] ),
        baseurl   =dict(default='https://api.digitalocean.com/v2/', required=False),
        url =dict(default='droplets', required=False),
        token = dict(required=True),
        ssh_keys = dict(default= [680960, 154691] ),
        name = dict(required=False),
        region = dict(default='sgp1'),
        size = dict(default='512mb'),
        image= dict(default='centos-6-5-x64'),
        ipv6=dict(default=False),
        private_networking =dict(default=True),
        backups =dict(default=False),
        user_data = dict(default=None),
      ),
    )

    method = module.params['method']
    baseurl = module.params['baseurl']
    raw_url = module.params['url']
    token = module.params['token']

    bl = ['name', 'region', 'size', 'image', 'ipv6', 'private_networking', 'backups', 'user_data']
    body = dict(zip( bl, [module.params[x] for x in bl ] ))

    url = urljoin(baseurl, raw_url)
    headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer {0}'.format(token),
    } 

    if method == 'get':
      try:
        #r = requests.get(url,headers=headers)
        r= list(req_gen(url,headers=headers))
        module.exit_json(msg='{0}'.format(r))
      except Exception as e:
        module.exit_json(msg='{0}'.format(e))
    elif method == 'post':
      try:
        r = requests.post(url,headers=headers,data=json.dumps(body))
        module.exit_json(msg='{0}'.format(r.json()))
      except Exception as e:
        module.exit_json(msg='{0}'.format(e))
    elif method == 'delete':
      try:
        r1 = requests.get(url,headers=headers)
        r1dict = r1.json()
        target = [d['id'] for d in r1dict['droplets'] if d['name'] == body['name']][0]
        durl = urljoin(baseurl,'droplets/{0}'.format(target))
        r = requests.delete(durl,headers=headers)
        module.exit_json(msg='{0}'.format(r.json()))
      except Exception as e:
        module.exit_json(msg='{0}'.format(e))
    module.exit_json(changed=False)

from ansible.module_utils.basic import *
import json
from urlparse import urlparse, parse_qs, urljoin
import requests


main()
