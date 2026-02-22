import json
import jwt
import logging
import time


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
        payload: dict[str, typing.Any] = jwt.decode(bearer_token, options={'verify_signature': False})
        is_authorized = True
    except:
        logger.warn("Exception thrown in JWT decode")
        pass

    return {
        'isAuthorized': is_authorized,
        'context': {
            'auth_time_ms': int((time.perf_counter() - start_time) * ms_in_s)
        },
    }

