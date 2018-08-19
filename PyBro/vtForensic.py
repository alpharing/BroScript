"""Run a VirusTotal Query on Extracted File Hashes"""
import os
import sys
import requests

# Local imports
from brothon import bro_log_reader

def checkVirus(Sha256):

    try:

        params = {'apikey': 'PUT YOUR API KEY',
                  'resource': Sha256}

        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  My Python requests library example client or username"
        }

        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                params=params, headers=headers)

        json_response = response.json(encoding='UTF8')

        # response_code = 0 -> could't find file
        if json_response['response_code'] == 1:
            print(str(json_response['positives']) + '/' + str(json_response['total']))
            print('more')
            print(json_response['permalink'])
        else:
            print('This file cannot be verified')

    except BaseException as e:
        print(e)

if __name__ == '__main__':
    """Run a VirusTotal Query on Extracted File Hashes"""

    index = 1

    try:
        # Run the bro reader on a given log file
        reader = bro_log_reader.BroLogReader('files.log')

        print('Examination result (positives / total number of vaccines)')

		# Use Sha1 hash algorithm
        for row in reader.readrows():
            print(index)
            index += 1

            if(row['sha1'] != '-'):
                checkVirus(row['sha1'])

    except BaseException as e:
        print(e)

