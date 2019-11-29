"""
IAM Account Enumerator

This code provides a mechanism to attempt to validate the permissions assigned
to a given set of AWS tokens.

Initial code from:

    https://gist.github.com/darkarnium/1df59865f503355ef30672168063da4e

Improvements:
    * Complete refactoring
    * Results returned in a programmatic way
    * Threads
    * Improved logging
    * Increased API call coverage
    * Export as a library
"""
import re
import json
import logging
import signal
import boto3
import botocore
import random

from botocore.client import Config
from botocore.endpoint import MAX_POOL_CONNECTIONS
from multiprocessing import TimeoutError
from multiprocessing.dummy import Pool as ThreadPool, Manager, Value

from enumerate_iam.utils.remove_metadata import remove_metadata
from enumerate_iam.utils.json_utils import json_encoder
from enumerate_iam.bruteforce_tests import BRUTEFORCE_TESTS

MAX_THREADS = 25
CLIENT_POOL = {}
MANAGER = Manager()
STOP_SIGNAL = MANAGER.Value('i', 0)


def report_arn(candidate):
    """
    Attempt to extract and slice up an ARN from the input string
    """
    logger = logging.getLogger()

    arn_search = re.search(r'.*(arn:aws:.*?) .*', candidate)

    if arn_search:
        arn = arn_search.group(1)

        arn_id = arn.split(':')[4]
        arn_path = arn.split(':')[5]

        logger.info('-- Account ARN : %s', arn)
        logger.info('-- Account Id  : %s', arn.split(':')[4])
        logger.info('-- Account Path: %s', arn.split(':')[5])

        return arn, arn_id, arn_path

    return None, None, None


def enumerate_using_bruteforce(access_key, secret_key, session_token, region, timeout):
    """
    Attempt to brute-force common describe calls.
    """
    global STOP_SIGNAL
    output = dict()

    logger = logging.getLogger()
    logger.info('Attempting common-service describe / list brute force.')

    original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    pool = ThreadPool(MAX_THREADS)
    signal.signal(signal.SIGINT, original_sigint_handler)

    args_generator = generate_args(access_key, secret_key, session_token, region, STOP_SIGNAL)

    try:
        results = pool.map_async(check_one_permission, args_generator)
        results.get(timeout)
    except TimeoutError:
        logger.info('Brute-forcing permissions timed out.')
        STOP_SIGNAL.value = 1

    except KeyboardInterrupt:
        STOP_SIGNAL.value = 1
        print('')

        results = []

        logger.info('Ctrl+C received, stopping all threads.')
        logger.info('Hit Ctrl+C again to force exit.')

        try:
            pool.close()
            pool.join()
        except KeyboardInterrupt:
            print('')
            return output

    for thread_result in results:
        if thread_result is None:
            continue

        key, action_result = thread_result
        output[key] = action_result

    pool.close()
    pool.join()

    return output


def generate_args(access_key, secret_key, session_token, region, stop_signal):

    service_names = list(BRUTEFORCE_TESTS.keys())

    random.shuffle(service_names)

    for service_name in service_names:
        actions = list(BRUTEFORCE_TESTS[service_name])
        random.shuffle(actions)

        for action in actions:
            yield access_key, secret_key, session_token, region, stop_signal, service_name, action


def get_client(access_key, secret_key, session_token, service_name, region):
    key = '%s-%s-%s-%s-%s' % (access_key, secret_key, session_token, service_name, region)

    client = CLIENT_POOL.get(key, None)
    if client is not None:
        return client

    logger = logging.getLogger()
    logger.debug('Getting client for %s in region %s' % (service_name, region))

    config = Config(connect_timeout=5,
                    read_timeout=5,
                    retries={'max_attempts': 30},
                    max_pool_connections=MAX_POOL_CONNECTIONS * 2)

    try:
        client = boto3.client(
            service_name,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region,
            verify=False,
            config=config,
        )
    except:
        # The service might not be available in this region
        return

    CLIENT_POOL[key] = client

    return client


def check_one_permission(arg_tuple):
    access_key, secret_key, session_token, region, stop_signal, service_name, operation_name = arg_tuple
    logger = logging.getLogger()

    if stop_signal.value == 1:
        return

    service_client = get_client(access_key, secret_key, session_token, service_name, region)
    if service_client is None:
        return

    try:
        action_function = getattr(service_client, operation_name)
    except AttributeError:
        # The service might not have this action (this is most likely
        # an error with generate_bruteforce_tests.py)
        logger.error('Remove %s.%s action' % (service_name, operation_name))
        return

    logger.debug('Testing %s.%s() in region %s' % (service_name, operation_name, region))

    if stop_signal.value == 1:
        return
    try:
        action_response = action_function()
    except (botocore.exceptions.ClientError,
            botocore.exceptions.EndpointConnectionError,
            botocore.exceptions.ConnectTimeoutError,
            botocore.exceptions.ReadTimeoutError):
        return
    except botocore.exceptions.ParamValidationError:
        logger.error('Remove %s.%s action' % (service_name, operation_name))
        return

    msg = '-- %s.%s() worked!'
    args = (service_name, operation_name)
    logger.info(msg % args)

    key = '%s.%s' % (service_name, operation_name)

    return key, remove_metadata(action_response)


def configure_logging(level):
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(process)d - [%(levelname)s] %(message)s',
    )

    # Suppress boto INFO.
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('nose').setLevel(logging.WARNING)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # import botocore.vendored.requests.packages.urllib3 as urllib3
    urllib3.disable_warnings(botocore.vendored.requests.packages.urllib3.exceptions.InsecureRequestWarning)


def enumerate_iam(access_key, secret_key, session_token, region, timeout, level = logging.INFO):
    """IAM Account Enumerator.

    This code provides a mechanism to attempt to validate the permissions assigned
    to a given set of AWS tokens.
    """
    output = dict()
    configure_logging(level)

    output['iam'] = enumerate_using_iam(access_key, secret_key, session_token, region)
    output['bruteforce'] = enumerate_using_bruteforce(access_key, secret_key, session_token, region, timeout)

    return output


def enumerate_using_iam(access_key, secret_key, session_token, region):
    output = dict()
    logger = logging.getLogger()

    # Connect to the IAM API and start testing.
    logger.info('Starting permission enumeration for access-key-id "%s"', access_key)
    iam_client = boto3.client(
        'iam',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )

    # Try for the kitchen sink.
    try:
        everything = iam_client.get_account_authorization_details()
    except (botocore.exceptions.ClientError,
            botocore.exceptions.EndpointConnectionError,
            botocore.exceptions.ReadTimeoutError):
        pass
    else:
        logger.debug('Run for the hills, get_account_authorization_details worked!')
        logger.debug('%s', json.dumps(everything, indent=4, default=json_encoder))

        output['iam.get_account_authorization_details'] = remove_metadata(everything)

    enumerate_user(iam_client, output)
    enumerate_role(iam_client, output)

    return output


def enumerate_role(iam_client, output):
    logger = logging.getLogger()

    # This is the closest thing we have to a role ARN
    user_or_role_arn = output.get('arn', None)

    if user_or_role_arn is None:
        # The checks which follow all required the user name to run, if we were
        # unable to get that piece of information just return
        return

    # Attempt to get role to start.
    try:
        role = iam_client.get_role(RoleName=user_or_role_arn)
    except botocore.exceptions.ClientError as err:
        arn, arn_id, arn_path = report_arn(str(err))

        if arn is not None:
            output['arn'] = arn
            output['arn_id'] = arn_id
            output['arn_path'] = arn_path

        if 'role' not in user_or_role_arn:
            # We did out best, but we got nothing from iam
            return
        else:
            role_name = user_or_role_arn

    else:
        output['iam.get_role'] = remove_metadata(role)
        role_name = role['Role']['RoleName']

    # Attempt to get policies attached to this user.
    try:
        role_policies = iam_client.list_attached_role_policies(RoleName=role_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_attached_role_policies'] = remove_metadata(role_policies)
        logger.debug('%s', json.dumps(role_policies, indent=4, default=json_encoder))

        logger.info(
            'Role "%s" has %0d attached policies',
            role['Role']['RoleName'],
            len(role_policies['AttachedPolicies'])
        )

        # List all policies, if present.
        for policy in role_policies['AttachedPolicies']:
            logger.info('-- Policy "%s" (%s)', policy['PolicyName'], policy['PolicyArn'])

            try:
                get_policy = iam.get_role_policy(PolicyName=policy['PolicyName'])
                policy_version = iam_client.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=policy['DefaultVersionId'])
                logger.debug('Role attached policy: {}'.format(policy['PolicyName'])) 
                logger.debug('%s', json.dumps(policy_version, indent=4, default=json_encoder))

                key = 'iam.role_attached_policies'
                if key not in output.keys(): output[key] = []
                output[key].append(remove_metadata(policy_version))
            except:
                pass

    # Attempt to get inline policies for this user.
    try:
        role_policies = iam_client.list_role_policies(RoleName=role_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_role_policies'] = remove_metadata(role_policies)

        logger.info(
            'Role "%s" has %0d inline policies',
            role['Role']['RoleName'],
            len(role_policies['PolicyNames'])
        )

        # List all policies, if present.
        for policy in role_policies['PolicyNames']:
            logger.info('-- Policy "%s"', policy)

            try:
                get_policy = iam_client.get_user_policy(RoleName=role_name, PolicyName=policy)
                logger.debug('Role inline policy:\n%s', json.dumps(get_policy['PolicyDocument'], indent=4, default=json_encoder))

                key = 'iam.role_inline_policies'
                if key not in output.keys(): output[key] = []
                output[key].append(remove_metadata(get_policy['PolicyDocument']))
            except:
                pass

    return output


def enumerate_user(iam_client, output):
    logger = logging.getLogger()
    output['root_account'] = False

    # Attempt to get user to start.
    try:
        user = iam_client.get_user()
    except botocore.exceptions.ClientError as err:
        arn, arn_id, arn_path = report_arn(str(err))

        output['arn'] = arn
        output['arn_id'] = arn_id
        output['arn_path'] = arn_path

        # The checks which follow all required the user name to run, if we were
        # unable to get that piece of information just return
        return
    else:
        output['iam.get_user'] = remove_metadata(user)

    if 'UserName' not in user['User']:
        if user['User']['Arn'].endswith(':root'):
            # OMG
            logger.warn('Found root credentials!')
            output['root_account'] = True
            return
        else:
            logger.error('Unexpected iam.get_user() response: %s' % user)
            return
    else:
        user_name = user['User']['UserName']

    # Attempt to get policies attached to this user.
    try:
        user_policies = iam_client.list_attached_user_policies(UserName=user_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_attached_user_policies'] = remove_metadata(user_policies)

        logger.info(
            'User "%s" has %0d attached policies',
            user_name,
            len(user_policies['AttachedPolicies'])
        )

        # List all policies, if present.
        for policy in user_policies['AttachedPolicies']:
            logger.info('-- Policy "%s" (%s)', policy['PolicyName'], policy['PolicyArn'])

            try:
                get_policy = iam_client.get_policy(PolicyArn=policy['PolicyArn'])
                policy_version = iam_client.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=get_policy['Policy']['DefaultVersionId'])
                logger.debug('User attached policy:\n%s', json.dumps(policy_version['PolicyVersion'], indent=4, default=json_encoder))

                key = 'iam.user_attached_policies'
                if key not in output.keys(): output[key] = []
                output[key].append(remove_metadata(policy_version['PolicyVersion']))
            except:
                pass

    # Attempt to get inline policies for this user.
    try:
        user_policies = iam_client.list_user_policies(UserName=user_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_user_policies'] = remove_metadata(user_policies)

        logger.info(
            'User "%s" has %0d inline policies',
            user_name,
            len(user_policies['PolicyNames'])
        )

        # List all policies, if present.
        for policy in user_policies['PolicyNames']:
            logger.info('-- Policy "%s"', policy)

            try:
                get_policy = iam_client.get_user_policy(UserName=user_name, PolicyName=policy)
                logger.debug('User inline policy:\n%s', json.dumps(get_policy['PolicyDocument'], indent=4, default=json_encoder))

                key = 'iam.user_inline_policies'
                if key not in output.keys(): output[key] = []
                output[key].append(remove_metadata(get_policy['PolicyDocument']))
            except:
                pass

    # Attempt to get the groups attached to this user.
    user_groups = dict()
    user_groups['Groups'] = []

    try:
        user_groups = iam_client.list_groups_for_user(UserName=user_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_groups_for_user'] = remove_metadata(user_groups)

        logger.info(
            'User "%s" has %0d groups associated',
            user_name,
            len(user_groups['Groups'])
        )

    # Attempt to get the group policies
    output['iam.list_group_policies'] = dict()

    for group in user_groups['Groups']:
        try:
            group_policy = iam_client.list_group_policies(GroupName=group['GroupName'])

            output['iam.list_group_policies'][group['GroupName']] = remove_metadata(group_policy)

            logger.info(
                '-- Group "%s" has %0d inline policies',
                group['GroupName'],
                len(group_policy['PolicyNames'])
            )

            # List all group policy names.
            for policy in group_policy['PolicyNames']:
                logger.info('---- Policy "%s"', policy)

                try:
                    get_policy = iam_client.get_group_policy(GroupName=group['GroupName'], PolicyName=policy)
                    logger.debug('Group inline policy:\n%s', json.dumps(get_policy['PolicyDocument'], indent=4, default=json_encoder))

                    key = 'iam.group_inline_policies'
                    if key not in output.keys(): output[key] = []
                    output[key].append(remove_metadata(get_policy['PolicyDocument']))
                except:
                    pass

        except botocore.exceptions.ClientError as err:
            pass

    return output

