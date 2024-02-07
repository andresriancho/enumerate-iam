#!/opt/homebrew/bin/python3
import argparse
import getpass

from enumerate_iam.main import enumerate_iam


def main():
    parser = argparse.ArgumentParser(description='Enumerate IAM permissions')

    parser.add_argument('--access-key', help='AWS access key')
    parser.add_argument('--secret-key', help='AWS secret key')
    parser.add_argument('--session-token', help='STS session token')
    parser.add_argument('--region', help='AWS region to send API requests to', default='us-east-1')

    args = parser.parse_args()

    if args.access_key is None:
        args.access_key = input("Enter AWS access key: ")

    if args.secret_key is None:
        args.secret_key = getpass.getpass("Enter AWS secret key: ")

    enumerate_iam(args.access_key,
                      args.secret_key,
                      args.session_token,
                      args.region)


if __name__ == '__main__':
    main()
