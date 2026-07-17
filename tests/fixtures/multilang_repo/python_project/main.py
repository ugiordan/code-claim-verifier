import os
import json

def parse_input(data):
    return json.loads(data)

def validate_token(token):
    return len(token) > 0

def handle_request(request):
    data = parse_input(request)
    return validate_token(data.get("token", ""))
