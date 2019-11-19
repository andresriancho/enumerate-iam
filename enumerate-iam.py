#!/usr/bin/env python
import sys
import argparse

from boto3 import Session
from enumerate_iam.main import enumerate_iam

def main():
    parser = argparse.ArgumentParser(description='Enumerate IAM permissions')

    parser.add_argument('--profile', help='AWS profile name fetched from credentials file. Specify this parameter or access-key and secret-key manually.')
    parser.add_argument('--access-key', help='AWS access key if profile was not used')
    parser.add_argument('--secret-key', help='AWS secret key if profile was not used')
    parser.add_argument('--session-token', help='STS session token')
    parser.add_argument('--region', help='AWS region to send API requests to', default='us-east-1')

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

    enumerate_iam(access_key,
                  secret_key,
                  session_token,
                  args.region)

if __name__ == '__main__':
    main()
