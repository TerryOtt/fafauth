import json
import logging


logger = logging.getLogger()


def custom_authorizer(event, context):
    """
    Handles the authorization logic.
    The event object contains the authorization token and method ARN.
    """
    # Extract the token from the event object, often from 'authorizationToken' header
    logger.info(f"Event: {json.dumps(event)}")

    """
    if token == os.environ.get('VALID_TOKEN'):
        # If valid, return an IAM policy allowing access
        return generatePolicy('user', 'Allow', event['methodArn'])
    else:
        # If invalid, raise an error to deny access (API Gateway handles the 401/403 response)
        # For a TOKEN authorizer, an 'Unauthorized' string response often results in a 401
        # while an explicit "Deny" policy results in a 403.
        print("Unauthorized attempt")
        raise Exception('Unauthorized')
    """

    return {
        'isAuthorized': True
    }

