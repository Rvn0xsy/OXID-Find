#!/usr/bin/env python
# coding: utf-8

from base64 import b64encode
from argparse import ArgumentParser, FileType
from Queue import Queue
from threading import Thread
import sys
import socket
import logging

TIME_OUT = 2
RESULT_LIST = []

def get_ip_list(ip):
    ip_list = []
    iptonum = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])
    numtoip = lambda x: '.'.join([str(x/(256**i)%256) for i in range(3,-1,-1)])
    if '-' in ip:
        ip_range = ip.split('-')
        ip_start = long(iptonum(ip_range[0]))
        ip_end = long(iptonum(ip_range[1]))
        ip_count = ip_end - ip_start
        if ip_count >= 0 and ip_count <= 65536:
            for ip_num in range(ip_start,ip_end+1):
                ip_list.append(numtoip(ip_num))
        else:
            print '-i wrong format'
    elif '.ini' in ip:
        ip_config = open(ip,'r')
        for ip in ip_config:
            ip_list.extend(get_ip_list(ip.strip()))
        ip_config.close()
    else:
        ip_split=ip.split('.')
        net = len(ip_split)
        if net == 2:
            for b in range(1,255):
                for c in range(1,255):
                    ip = "%s.%s.%d.%d"%(ip_split[0],ip_split[1],b,c)
                    ip_list.append(ip)
        elif net == 3:
            for c in range(1,255):
                ip = "%s.%s.%s.%d"%(ip_split[0],ip_split[1],ip_split[2],c)
                ip_list.append(ip)
        elif net ==4:
            ip_list.append(ip)
        else:
            print "-i wrong format"
    return ip_list

def str_to_hex(s):
    return r"/x"+r'/x'.join([hex(ord(c)).replace('0x', '') for c in s])

def get_addres(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(TIME_OUT)
        sock.connect((ip,135))
        buffer_v1 = "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\xc4\xfe\xfc\x99\x60\x52\x1b\x10\xbb\xcb\x00\xaa\x00\x21\x34\x7a\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00"
        buffer_v2 = "\x05\x00\x00\x03\x10\x00\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00"
        sock.send(buffer_v1)
        packet = sock.recv(1024)
        sock.send(buffer_v2)
        packet = sock.recv(4096)
        packet_v2 = packet[42:]
        packet_v2_end = packet_v2.find("\x09\x00\xff\xff\x00\x00")
        packet_v2 = packet_v2[:packet_v2_end]
        hostname_list = packet_v2.split("\x00\x00")
        result = {ip:[]}
        print("[*] " + ip)
        for h in hostname_list:
            h = h.replace('\x07\x00','')
            h = h.replace('\x00','')
            if h == '':
                continue
            print("\t[->]" + h)
            result[ip].append(h)
        print result
        return result
    except Exception as e:
        return -1
    finally:
        sock.close()

def worker(q):
    while True:
        try:
            data = q.get()
            result = get_addres(data)
            if result is not -1:
                RESULT_LIST.append(result)
        except Exception as e:
            sys.stderr.write(str(e))
        finally:
            q.task_done()


def main():
    parser = ArgumentParser()
    parser.add_argument('-i', '--ip', help=u'IP Address', required=True)
    parser.add_argument('-t', '--threads', help=u'threads', default=20, type=int)
    parser.add_argument('-o', '--output', help=u'Output result', default='log.txt', type=FileType('a+'))
    
    args = parser.parse_args()
    if args.ip is None:
        print("Some Wrong.")
    q = Queue(args.threads)

    for _ in xrange(args.threads):
        t = Thread(target=worker, args=(q,))
        t.daemon = True
        t.start()

    ip_list = get_ip_list(args.ip)
    for i in ip_list:
        q.put(i)
    q.join()

    for host in RESULT_LIST:
        for ip in host.keys():
            args.output.write("[*] " + ip + "\n")
            for other_ip in host[ip]:
                args.output.write("\t[->] " + other_ip + "\n")

if __name__ == '__main__':
    main()
