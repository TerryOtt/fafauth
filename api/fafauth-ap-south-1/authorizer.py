import json
import logging


logger = logging.getLogger()



def custom_authorizer(event, context):
    """
    Handles the authorization logic.
    The event object contains the authorization token and method ARN.
    """
    # Extract the token from the event object, often from 'authorizationToken' header
    token = event.get('authorizationToken')
    logger.info(f"Auth token passed: {token}")

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

    return generatePolicy('user', 'Allow', event['methodArn'])



def generatePolicy(principalId, effect, resource):
    """
    Generates the IAM policy document for the authorizer.
    """
    authResponse = {
        'principalId': principalId
    }

    if effect and resource:
        policyDocument = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': resource
                }
            ]
        }
        authResponse['policyDocument'] = policyDocument
        
    # Optional: You can also return a context map (key-value pairs)
    # authResponse['context'] = {'key': 'value'}
    
    return authResponse

