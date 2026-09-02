#!/usr/bin/env python3
"""
FRP Dictionary Generator — generates a targeted password list for FRP brute force.

Usage:
  python3 frp_dict_gen.py > frp_passwords.txt

Generates ~6000 passwords from:
  - FRP-related keywords (frp, fatedier, proxy, tunnel, etc.)
  - Common admin passwords with various suffixes
  - Pattern combinations (base + year, base + symbols, etc.)
"""
import sys

bases = [
    'admin', 'root', 'frp', 'frps', 'frpc', 'proxy', 'node', 'server',
    'tunnel', 'manager', 'operator', 'test', 'demo', 'user', 'system',
    'default', 'info', 'guest', 'support', 'dev', 'ops', 'super',
    'gateway', 'relay', 'forward', 'access', 'client', 'master',
    'control', 'panel', 'dash', 'manage', 'pass', 'key', 'secret',
    'fatedier', 'gofrp', 'fastproxy', 'reverse', 'nat'
]

suffixes = [
    '', '123', '1234', '12345', '123456', '1234567', '12345678',
    '!', '@', '#', '$', '!@#', '@123', '!123', '#123',
    '2024', '2025', '2026', '1', '12', '0', '00', '000', '01',
    'admin', 'pass', 'password', 'test', 'demo', 'root', 'frp', 'proxy',
    '!@#$', '@dmin', 'ADMIN'
]

specials = [
    'admin', 'admin123', 'admin123456', 'admin@123', 'Admin@123',
    'administrator', 'Administrator', 'Admin123', 'ADMIN',
    'password', 'password123', 'Password', 'PASSWORD',
    '123456', '12345678', '123456789', '1234567890',
    'root', 'root123', 'root@123', 'root123456', 'Root123',
    'frp', 'frp123', 'frpadmin', 'frp@123', 'frp2024',
    'Frp123', 'Frp@123', 'FRP123',
    'P@ssw0rd', 'p@ssw0rd', 'Passw0rd', 'passw0rd',
    'qwerty', 'qwerty123', '1q2w3e4r', '1q2w3e4r5t',
    '1qaz2wsx', '3edc4rfv', 'zaq1xsw2', 'xsw2zaq1',
    'abc123', 'ABC123', 'Abc123',
    'passwd', 'passwd123', 'Passwd',
    'admin!', 'admin!@#', 'admin!@#$',
    'admin2024', 'admin2025', 'admin2026',
    'root2024', 'root2025', 'root2026',
    'frp2024', 'frp2025', 'frp2026',
    'manager', 'manager123', 'Manager', 'Manager123',
    'operator', 'operator123', 'Operator',
    'test', 'test123', 'testing',
    'demo', 'demo123', 'demo!',
    'user', 'user123', 'User123',
    'guest', 'guest123',
    'server', 'server123',
    'proxy', 'proxy123', 'proxy@123',
    'tunnel', 'tunnel123',
    'node', 'node123', 'node1', 'node01',
    'access', 'access123',
    'relay', 'relay123',
    'control', 'control123',
    'panel', 'panel123',
    'fatedier', 'fatedier123',
    'gofrp', 'gofrp123',
    'nat', 'nat123',
    'default', 'default123',
    'superadmin', 'superadmin123',
    'supersecure', 'changeme',
    'letmein', 'welcome',
    'pass@123', 'Pass@123',
    'passw0rd!', 'P@$$w0rd',
    'sangfor', 'ruijie', 'cisco', 'huawei', 'h3c',
]

def gen():
    passwords = set()
    for b in bases:
        passwords.add(b)
        passwords.add(b.capitalize())
        passwords.add(b.upper())
        for s in suffixes:
            passwords.add(b + s)
            passwords.add(b.capitalize() + s)
            if s:
                passwords.add(b + '_' + s)
                passwords.add(b + '-' + s)
    for s in specials:
        passwords.add(s)
    for p in sorted(set(passwords), key=lambda x: (len(x), x)):
        print(p)

if __name__ == "__main__":
    gen()
