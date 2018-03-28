import argparse
import subprocess
import re
import requests
import sys

IP_PATTERN = re.compile('\d+\.\d+\.\d+\.\d+')
TRACERT_LINE_PATTERN = re.compile('\d+\s+.*\r\n')
IPINFO_URL = 'https://ipinfo.io/'


def get_or_unknown(some):
    if some:
        return some
    else:
        return 'unknown'


class IP_Info:
    def __init__(self, ip):
        self.ip = ip
        self.org, self.country = self._who_is()

    def __str__(self):
        return 'ip: {0}, org: {1}, country: {2}'.format(self.ip, self.org,
                                                        self.country)

    def _who_is(self):
        response = requests.request('get', IPINFO_URL + self.ip).json()
        return get_or_unknown(response.get('org')), get_or_unknown(
            response.get('country'))


def get_ips_from_tracert(address):
    try:
        tracert_route = subprocess.check_output(['tracert', address]).decode('cp866')
    except subprocess.CalledProcessError:
        sys.exit()
    hops_info = TRACERT_LINE_PATTERN.findall(tracert_route)
    ips = []
    for hop in hops_info:
        match = IP_PATTERN.search(hop)
        if match:
            ip = match.group()
        else:
            ip = "unknown"
        ips.append(ip)
    return ips


def get_info(ips):
    infos = []
    for ip in ips:
        infos.append(IP_Info(ip))
    return infos


def trace_route(address):
    ips = get_ips_from_tracert(address)
    infos = get_info(ips)
    for i, info in enumerate(infos):
        print(str(i) + ' ' + str(info) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('domain', help='domain to trace')
    address = parser.parse_args().domain
    trace_route(address)
