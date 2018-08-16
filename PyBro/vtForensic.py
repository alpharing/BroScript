"""Run a VirusTotal Query on Extracted File Hashes"""
from __future__ import print_function

import os
import sys
import argparse
import requests

from pprint import pprint

# Local imports
from brothon import bro_log_reader
from brothon.utils import vt_query


def checkVirus(Sha256):

    try:

        params = {'apikey': 'PUT YOUR VT-API KEY',
                  'resource': Sha256}

        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  My Python requests library example client or username"
        }

        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                params=params, headers=headers)

        json_response = response.json(encoding='UTF8')

        print(json_response['positives'])
        print(str(json_response['total']))


    except BaseException as e:
        print(e)

if __name__ == '__main__':
    """Run a VirusTotal Query on Extracted File Hashes"""


    try:
        # Run the bro reader on a given log file
        reader = bro_log_reader.BroLogReader('files.log')

        for row in reader.readrows():
            if(row['sha1'] != '-'):
                checkVirus(row['sha1'])

    except BaseException as e:
        print(e)

