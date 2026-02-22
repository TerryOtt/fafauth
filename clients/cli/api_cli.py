import argparse
import datetime
import json
import jwt
import logging
import requests
import time
import typing

logger: logging.Logger = logging.getLogger()


known_commands: dict[str, dict[str, typing.Any]] = {
    "ping": {
        "function": requests.get,
        "endpoint": "/api/v001/ping",
    }
}

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("api_address", help="IP address or DNS hostname of endpoint")
    parser.add_argument("operation", help="Operation to perform",
                        choices=known_commands.keys())
    parser.add_argument("bearer_token", help="OIDC bearer token to send to api")
    return parser.parse_args()


def _validate_bearer_token(bearer_token: str) -> None:
    payload: dict[str, typing.Any] = jwt.decode(bearer_token,
        options={'verify_signature': False})
    expiration_time = payload.get('exp')
    if expiration_time is None:
        raise ValueError("Bearer token had no expiration time field")
    expiration_time = datetime.datetime.fromtimestamp(expiration_time, tz=datetime.timezone.utc)
    seconds_remaining: int  = int((expiration_time - datetime.datetime.now(tz=datetime.timezone.utc)).total_seconds())
    if seconds_remaining < 15:
        raise ValueError("Bearer token is expired")
    if seconds_remaining < 300:
        print("WARNING: Bearer token expires within FIVE minutes!")
    if seconds_remaining < 600:
        print("INFO: Bearer token expires within ten minutes")

    if seconds_remaining > 3600:
        time_remaining: str = f"{seconds_remaining / 3600:.01f} hours"
    else:
        time_remaining = f"{seconds_remaining // 60:d} minutes"
    logger.debug(f"Bearer token expires in {time_remaining}")


def _run_cmd(args: argparse.Namespace) -> None:
    url_to_hit: str = f"{args.api_address}{known_commands[args.operation]['endpoint']}"
    start_time: float = time.perf_counter()
    response: requests.Response = known_commands[args.operation]['function'](url_to_hit)
    end_time: float = time.perf_counter()
    response.raise_for_status()
    print(f"\nRound trip time: {int((end_time - start_time) * 1000):,} ms")
    print(f"\nResponse:\n{json.dumps(response.json(), indent=4, sort_keys=True)}\n")


def _main() -> None:
    logging.basicConfig(level=logging.DEBUG)
    args: argparse.Namespace = _parse_args()
    _validate_bearer_token(args.bearer_token)
    _run_cmd(args)


if __name__ == '__main__':
    _main()

