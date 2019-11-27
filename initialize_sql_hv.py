#!/usr/bin/python
import sys, hvac, string
from random import choice

def generate_password(charset=None, length=32):
    """Generates a random password. Probably not very secure, but it's OK for my lab."""
    if charset is None:
        charset = string.ascii_letters + string.digits + '!@#$%^&*()-_=+<>./?,;:[]{}\|~'
    
    return ''.join([choice(charset) for _ in xrange(length)])

def initialize_secret(vault, secret_name, secrets={}):
    """Checks the contents of a the secrets dict and populates values as
    required. It also updates Vaults with new values."""
    if 'root_password' not in secrets:
        secrets['root_password'] = generate_password(charset)
    
    if 'db_name' not in secrets:
        secrets['db_name'] = secret_name

    if 'db_user' not in secrets:
        secrets['db_user'] = secret_name

    if 'db_user_password' not in secrets:
        secrets['db_user_password'] = generate_password(charset)

    vault.secrets.kv.v1.create_or_update_secret(
        path='sql/%s' % secret_name,
        secret=secrets,
    )

    print("changes")
    exit(0)

if len(sys.argv) != 4:
    print('Role ID, Secret ID, and vault name are required')
    exit(1)

role_id = sys.argv[1]
secret_id = sys.argv[2]
secret_name = sys.argv[3]

required_secret_fields = [
    'root_password',
    'db_name',
    'db_user',
    'db_user_password'
]

# This is the charset used by the generate_password function by default
# It exists here so that generate_charset doesn't have to append these strings
# together multiple times.
charset = string.ascii_letters + string.digits + '!@#$%^&*()-_=+<>./?,;:[]{}\|~'

vault = hvac.Client(url='https://** redacted **:8200')
vault.auth_approle(role_id, secret_id)

if not vault.is_authenticated():
    print('Provided Role ID and Secret ID are not valid.')
    exit (1)

try:
    # Retreive any existing secret data for this secret name
    secrets = vault.secrets.kv.v1.read_secret(
        path='sql/%s' % secret_name,
        mount_point='secret'
    )['data']

    # If all required fields are already present then exit immediately
    # Otherwise call initialize_secrets to populate what is missing
    if all([key in secrets for key in required_secret_fields]):
        print("no_changes")
        exit(0)
    else:
        # initialize_secret will exit(0)
        initialize_secret(vault, secret_name, secrets)
        

# Secret does not exist, so create it
except hvac.exceptions.InvalidPath:
    # initialize_secret will exit(0)
    initialize_secret(vault, secret_name)