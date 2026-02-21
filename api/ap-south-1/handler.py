import json
import logging

logger = logging.getLogger()
logger.setLevel("DEBUG")


def ping(event, context):

    logger.debug("Entered")

    body = {
        "message": "Pong!",
    }

    response = {
        "statusCode"    : 200, 
        "headers": {
            "Content-Type": "application/json",
        },
        "body"          : json.dumps(body, indent=4, sort_keys=True), 
    }

    return response

