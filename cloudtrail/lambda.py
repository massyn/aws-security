import json
import os
import urllib.request
import urllib.parse

def handler(event, context):
    msg = ':warning: EventBridge Alert :warning:\n'
    for key in event:
        msg += '*{key}*\n{value}\n\n'.format(key = key, value=event[key])

    req = urllib.request.Request(
        os.environ['SLACK_WEBHOOK'],
        json.dumps({'text': msg}).encode('utf-8'),
        {'Content-Type': 'application/json'}
    )
    resp = urllib.request.urlopen(req)
    return { 'statusCode': 200 }
