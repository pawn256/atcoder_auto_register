#!/usr/bin/python
# -*- coding:utf-8 -*-

from mycrypt import AESCipher as aes
import os
import sys
import re
import requests
from urllib.parse import urlencode,quote,unquote,urlparse
from bs4 import BeautifulSoup

def printdbg(s):
    global debug
    if debug: print(s)

def get_csrf_token(req):
    bs=BeautifulSoup(req.text,'lxml')
    return [(i['value']) for i in bs.select('input',name='csrf_token')[:1]].pop()

def get(url,headers={}):
    return requests.get(url,headers=headers)

def post(url,params,headers):
    params = urlencode(params)
    return requests.post(url,data=params,headers=headers)

def extract_cookie(cookie,key):
    return re.match(r'(.*)({}=)(.*?);.*'.format(key),cookie).group(3)

def get_user():
    encpass=os.environ['ATCODER_ENCUSER']
    key=os.environ['HOSTNAME']
    a=aes(key)
    return a.decrypt(encpass)

def get_pass():
    encpass=os.environ['ATCODER_ENCPASS']
    key=os.environ['HOSTNAME']
    a=aes(key)
    return a.decrypt(encpass)

def login():
    url='https://atcoder.jp/login'
    req=get(url)
    csrf_token=get_csrf_token(req)
    printdbg(csrf_token)
    params = {
            'csrf_token': csrf_token,
            'username': get_user(),
            'password': get_pass()
            }
    revel_session=extract_cookie(req.headers['Set-Cookie'],'REVEL_SESSION')
    headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': 'REVEL_SESSION={};'.format(revel_session)
            }
    printdbg(headers)
    return post(url,params,headers)

def set_csrf_token(revel_session, token):
    # return a string for cookie.
    printdbg('{}, {}'.format(revel_session,token))
    return quote('\x00'.join(list(map(lambda x: 'csrf_token:{}'.format(token) if x.count('csrf_token')>0 else x, unquote(revel_session).split('\x00')))))

def get_schema_domain(url):
    # convert https://www.example.com/path to https://www.example.com.
    return '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(url))

def extract_action(bs,contests_name,path):
    return list(filter(lambda x: 'contests' in x.parent.attrs['action'] and contests_name in x.parent.attrs['action'] and path in x.parent.attrs['action'], bs.select('input')))

def get_register_action_csrf_token(req, contests_name):
    bs=BeautifulSoup(req.text,'lxml')
    l=extract_action(bs, contests_name, '/register').pop()
    return [l.parent.attrs['action'], l.attrs['value']]

def get_rated_register_action_csrf_token(req, contests_name):
    bs=BeautifulSoup(req.text,'lxml')
    l=extract_action(bs, contests_name, '/rated_register').pop()
    return [l.parent.attrs['action'], l.attrs['value']]

def detect_rated(req, contests_name):
    bs=BeautifulSoup(req.text,'lxml')
    return len(extract_action(bs, contests_name, '/rated_register')) > 0

def get_contests_page(url,req):
    revel_session=extract_cookie(req.headers['Set-Cookie'],'REVEL_SESSION')
    headers={
            'Cookie': 'REVEL_SESSION={};'.format(revel_session)
            }
    req=get(url,headers)
    printdbg('contests page {}'.format(req))
    return req

def create_url_action(url,action):
    return '{}{}'.format(get_schema_domain(url), action)

def register(url,req,contests_name):
    # get register form action and csrf_token
    action, csrf_token=get_register_action_csrf_token(req, contests_name)
    printdbg('action:{}, csrf_token:{}'.format(action,csrf_token))

    # set csrf_token
    revel_session=extract_cookie(req.headers['Set-Cookie'],'REVEL_SESSION')
    set_csrf_token(revel_session, csrf_token)

    # create register url and params,headers
    register_url=create_url_action(url,action)
    params = {
            'csrf_token': csrf_token,
            }
    headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': 'REVEL_SESSION={};'.format(revel_session)
            }

    printdbg('register_url:{}, headers:{}'.format(register_url,headers))
    # register
    req=post(register_url,params,headers)
    printdbg('register {}'.format(req))
    return req

def rated_register(url,req,contests_name,rated=True):
    # get register form action and csrf_token
    action, csrf_token=get_rated_register_action_csrf_token(req, contests_name)
    printdbg('action:{}, csrf_token:{}'.format(action,csrf_token))

    # set csrf_token
    revel_session=extract_cookie(req.headers['Set-Cookie'],'REVEL_SESSION')
    set_csrf_token(revel_session, csrf_token)

    # create register url and params,headers
    register_url=create_url_action(url,action)
    params = {
            'csrf_token': csrf_token,
            'rated': rated
            }
    headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': 'REVEL_SESSION={};'.format(revel_session)
            }

    printdbg('register_url:{}, headers:{}'.format(register_url,headers))
    # register
    req=post(register_url,params,headers)
    printdbg('register {}'.format(req))
    return req

def check_registered(req,contests_name):
    bs=BeautifulSoup(req.text,'lxml')
    return len(extract_action(bs, contests_name, '/unregister')) > 0

def usage():
    print("""Usage: python atcoder_auto_register <contest name>
 -h, --help, --usage        Get help for commands
 --debug                    Output debug log

 e.g. 'python atcoder_auto_register abc297'""")

def main():
    if '--usage' in sys.argv or '--help' in sys.argv or '-h' in sys.argv:
        usage()
    else:
        global debug
        contests_name=sys.argv[1]
        debug='--debug' in sys.argv
        url='https://atcoder.jp/contests/{}'.format(contests_name)
        printdbg(contests_name)
        # login
        req=login()
        printdbg('login {}'.format(req))

        # get contests page
        req=get_contests_page(url,req)

        if check_registered(req,contests_name):
            # check if it is already registered
            printdbg('already registered')
        elif detect_rated(req,contests_name):
            # rated register
            req=rated_register(url,req,contests_name)
            printdbg('rated regsiter {}'.format(req))
        else:
            # register
            req=register(url,req,contests_name)
            printdbg('regsiter {}'.format(req))

            # rated register
            req=rated_register(url,req,contests_name)
            printdbg('rated regsiter {}'.format(req))

if __name__ == '__main__':
    main()
