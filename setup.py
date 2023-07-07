#!/usr/bin/env python
import argparse

from enumerate_iam.main import enumerate_iam


def main():
    parser = argparse.ArgumentParser(description='Enumerate IAM permissions')

    parser.add_argument('--access-key', help='AWS access key', required=True)
    parser.add_argument('--secret-key', help='AWS secret key', required=True)
    parser.add_argument('--session-token', help='STS session token')
    parser.add_argument('--region', help='AWS region to send API requests to', default='us-east-1')

    args = parser.parse_args()

    enumerate_iam(args.access_key,
                  args.secret_key,
                  args.session_token,
                  args.region)


if __name__ == '__main__':
    main()
