#!/usr/bin/env python3
import sys
import json
import logging
import argparse

from boto3 import Session
from enumerate_iam.main import enumerate_iam
from enumerate_iam.utils.json_utils import json_encoder

def main():
    parser = argparse.ArgumentParser(description='Enumerate IAM permissions')

    parser.add_argument('--profile', help='AWS profile name fetched from credentials file. Specify this parameter or access-key and secret-key manually.')
    parser.add_argument('--access-key', help='AWS access key if profile was not used')
    parser.add_argument('--secret-key', help='AWS secret key if profile was not used')
    parser.add_argument('--session-token', help='STS session token')
    parser.add_argument('--region', help='AWS region to send API requests to', default='us-east-1')
    parser.add_argument('--output', help='File to write output JSON containing all of the collected permissions')
    parser.add_argument('--timeout', help='Timeout in minutes for permissions brute-forcing activity. Def: 15.', type=int, default=15)
    #parser.add_argument('--verbose', action='store_true', help='Enable verbose output.')
    parser.add_argument('--debug', action='store_true', help='Enable debug output.')

    args = parser.parse_args()

    if args.profile and (args.access_key or args.secret_key or args.session_token):
        sys.stderr.write('error: Profile and raw AWS credential options are mutually exclusive.\n')
        sys.stderr.write('       Please specify either --profile or --access-key and --secret-key.\n\n')
        parser.print_help()
        sys.exit(2)

    access_key = args.access_key
    secret_key = args.secret_key
    session_token = args.session_token

    if args.profile:
        session = Session(profile_name = args.profile)
        credentials = session.get_credentials()
        currcreds = credentials.get_frozen_credentials()
        access_key = currcreds.access_key
        secret_key = currcreds.secret_key
        session_token = currcreds.token

    level = logging.INFO
    if args.debug:
        level = logging.DEBUG

    output = enumerate_iam(access_key,
                  secret_key,
                  session_token,
                  args.region,
                  args.timeout * 60,
                  level)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(json.dumps(output, indent=4, default=json_encoder))

if __name__ == '__main__':
    main()
