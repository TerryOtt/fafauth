import boto3
import json
import jwt
import logging
import time


aws_region: str = "af-south-1"

ssm_client = boto3.client('ssm')

logger = logging.getLogger()
logger.setLevel('DEBUG')

ms_in_s: int = 1000

client_token_signing_jwks_param_store_path: str = "/fafauth/apigw_custom_authorizer/client_token_signing_keys_jwks"


def custom_authorizer(event, context):
    start_time: float = time.perf_counter()
    

    is_authorized: bool = False

    """
    Handles the authorization logic.
    The event object contains the authorization token and method ARN.
    """
    # Extract the token from the event object, often from 'authorizationToken' header
    logger.debug(f"Event: {json.dumps(event)}")
    bearer_token = None
    if 'headers' not in event or 'authorization' not in event['headers']:
        return {
            'isAuthorized': is_authorized,
            'context': {
                'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
            },
        }
    auth_string = event['headers']['authorization']
    logger.debug(f"Got Authorization value: \"{auth_string}\"")
    tokens = auth_string.split(' ')
    if not len(tokens) == 2 or not tokens[0] == "Bearer":
        return {
            'isAuthorized': is_authorized,
            'context': {
                'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
            },
        }

    bearer_token = tokens[1]
    logger.info(f"Got bearer token \"{bearer_token}\"")

    try:
        # Read JWKS from Kinde with public key of public/private pair used to sign all bearer tokens
        parameter_store_response = ssm_client.get_parameter( Name=client_token_signing_jwks_param_store_path )
    except:
        logger.error("Exception thrown in Param Store Read")
        return {
            'isAuthorized': is_authorized,
            'context': {
                'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
            },
        }

    if not 'Parameter' in parameter_store_response and not 'Value' in parameter_store_response['Parameter']:
        logger.error("Parameter store response did not have a value")
        
        return {
            'isAuthorized': is_authorized,
            'context': {
                'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
            },
        }

    jwks_str: str = parameter_store_response['Parameter']['Value']
    logger.info("Got JWKS JSON string from Parameter Store")
    jwks_dict: dict[str, list[dict[str, str]]] = json.loads(jwks_str)
    logger.info( json.dumps(jwks_dict, indent=4, sort_keys=True) )

    # Get key ID of signing key
    try:
        unverified_header = jwt.get_unverified_header(bearer_token)
        signing_kid: str = unverified_header['kid']
    except:
        logger.error("Bearer token had no key id (\"kid\") field")
        return {
            'isAuthorized': is_authorized,
            'context': {
                'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
            },
        }

    signing_rsa_public_key = None
    # Make sure signing JWKS has matching key 
    try:
        for curr_signing_jwk in jwks_dict['keys']:
            if 'kid' not in curr_signing_jwk:
                logger.error("Signing key did not have kid field")
                return {
                    'isAuthorized': is_authorized,
                    'context': {
                        'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
                    },
                }
            if curr_signing_jwk['kid'] == signing_kid:
                # Parse into format jwk can handle
                #
                # Note: jwt.algorithms is not a package, so you just import jwt and you get it
                signing_rsa_public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks_str)
                logger.info("Found matching signing key in JWKS and successfully created RSA public key from it")
                break

        # cute Python syntax if a for loop that should end early doesn't hits this case
        else:
            logger.warn(f"Bearer token claimed its signing key has key id of \"{signing_kid}\" which isn't in JWKS")
            return {
                'isAuthorized': is_authorized,
                'context': {
                    'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
                },
            }

    except:
        logger.error("Exception thrown during setting up signing key")
        return {
            'isAuthorized': is_authorized,
            'context': {
                'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
            },
        }


    # We are guaranteed to have a valid RSA public key in signing_rsa_public_key be

    
    try:
        payload: dict[str, typing.Any] = jwt.decode(bearer_token, options={'verify_signature': False})
        is_authorized = True
    except:
        logger.error("Exception thrown in JWT decode")

    return {
        'isAuthorized': is_authorized,
        'context': {
            'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
        },
    }

