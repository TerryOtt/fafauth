import json
import logging


logger = logging.getLogger()
logger.setLevel('DEBUG')


def custom_authorizer(event, context):
    """
    Handles the authorization logic.
    The event object contains the authorization token and method ARN.
    """
    # Extract the token from the event object, often from 'authorizationToken' header
    logger.debug(f"Event: {json.dumps(event)}")
    bearer_token = None
    if 'headers' in event:
        if 'authorization' in event['headers']:
            auth_string = event['headers']['authorization']
            logger.debug(f"Got Authorization value: \"{auth_string}\"")
            tokens = auth_string.split(' ')
            if len(tokens) == 2 and tokens[0] == "Bearer":
                bearer_token = tokens[1]
                logger.info(f"Got bearer token \"{bearer_token}\"")

    if not bearer_token:
        is_authorized = True
    else:   
        is_authorized = bearer_token == "faffaffaf"

    return {
        'isAuthorized': is_authorized
    }

