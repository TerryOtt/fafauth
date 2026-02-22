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

client_token_signing_jwks_param_store_paths: list[str] = [
    "/fafauth/apigw_custom_authorizer/client_token_signing_keys_jwks",
    "/fafauth/apigw_custom_authorizer/token_claims_validation_values",
]


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
        # Read two config values we need:
        #   1. JWKS from Kinde with public key of public/private pair used to sign all bearer tokens
        #   2. correct/expected values for aud and iss in the decoded bearer token
        parameter_store_response = ssm_client.get_parameters( Names=client_token_signing_jwks_param_store_paths )
    except Exception as e:
        logger.error("Exception thrown in Param Store Read: {e}")
        return {
            'isAuthorized': is_authorized,
            'context': {
                'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
            },
        }

    if not 'Parameters' in parameter_store_response or (
            len(parameter_store_response['Parameters']) != len(client_token_signing_jwks_param_store_paths) ): 
        logger.error("Parameter store response did not have our config values")
        
        return {
            'isAuthorized': is_authorized,
            'context': {
                'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
            },
        }

    for curr_config_entry in parameter_store_response['Parameters']:
        if curr_config_entry['Name'] == '/fafauth/apigw_custom_authorizer/client_token_signing_keys_jwks':
            jwks_str: str = curr_config_entry['Value']
            logger.info("Got JWKS JSON string from Parameter Store")
            jwks_dict: dict[str, list[dict[str, str]]] = json.loads(jwks_str)
            logger.info( json.dumps(jwks_dict, indent=4, sort_keys=True) )
        elif curr_config_entry['Name'] == '/fafauth/apigw_custom_authorizer/token_claims_validation_values':
            valid_values: str = curr_config_entry['Value']
            logger.info("Got expected aud/iss claim values from Parameter Store")
            correct_claim_values: dict[str, str] = json.loads(valid_values)

            # Verify length and contents
            if len(correct_claim_values) < 2 or 'aud' not in correct_claim_values or 'iss' not in correct_claim_values:
                raise RuntimeError(f"Didn't get two required aud and iss from Param Store: {valid_values}")

            logger.info(f"Correct values: {json.dumps(correct_claim_values, indent=4, sort_keys=True)}")

        else:
            logger.warn(f"Unexpected Param Store value returned: {curr_config_entry['Name']}")
            return {
                'isAuthorized': is_authorized,
                'context': {
                    'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
                },
            }

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
                signing_key_algo = curr_signing_jwk['alg']

                if signing_key_algo != "RS256":
                    logger.warn(f"Unsupported/unexpected signing key algorithm: {signing_key_algo}")
                    return {
                        'isAuthorized': is_authorized,
                        'context': {
                            'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
                        },
                    }

                # Parse into format jwk can handle
                #
                # Note: jwt.algorithms is not a package, so you just import jwt and you get it
                signing_rsa_public_key = jwt.algorithms.RSAAlgorithm.from_jwk(curr_signing_jwk)
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

    except Exception as e:
        logger.error(f"Exception thrown during setting up signing key: {e}")
        return {
            'isAuthorized': is_authorized,
            'context': {
                'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
            },
        }


    # We are guaranteed to have a valid RSA public key in signing_rsa_public_key at this point
    
    try:
        #payload: dict[str, typing.Any] = jwt.decode(bearer_token, options={'verify_signature': False})
        payload: dict[str, typing.Any] = jwt.decode(bearer_token, key=signing_rsa_public_key, algorithms=[signing_key_algo, ],
                                                    audience=correct_claim_values['aud'], 
                                                    issuer=correct_claim_values['iss'] )

        logger.info("Passed decoding, signature check, and valid aud/iss claims on bearer token, we're good in the hood")
        logger.info(json.dumps(payload, indent=4, sort_keys=True))
        is_authorized = True
    except Exception as e:
        logger.info(f"Exception thrown in JWT decode with signature check: {e}")

    return {
        'isAuthorized': is_authorized,
        'context': {
            'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
        },
    }

