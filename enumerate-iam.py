#!/usr/bin/env python
import argparse
import os

from enumerate_iam.main import enumerate_iam


def main():
    parser = argparse.ArgumentParser(description='Enumerate IAM permissions')

    # Allow specifying values from the environment
    access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    session_token = os.environ.get('AWS_SESSION_TOKEN')
    region = os.environ.get('AWS_REGION', os.environ.get('AWS_DEFAULT_REGION'))
    if region is None:
        region = 'us-east-1'

    # If not specified in the environment, these values need to be passed through the CLI
    parser.add_argument('--access-key', help='AWS access key', required=(access_key is None), default=access_key)
    parser.add_argument('--secret-key', help='AWS secret key', required=(secret_key is None), default=secret_key)
    parser.add_argument('--session-token', help='STS session token', required=(session_token is None), default=session_token)
    parser.add_argument('--region', help='AWS region to send API requests to', default=region)

    args = parser.parse_args()

    enumerate_iam(args.access_key,
                  args.secret_key,
                  args.session_token,
                  args.region)


if __name__ == '__main__':
    main()
