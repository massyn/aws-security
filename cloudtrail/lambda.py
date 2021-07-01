import json
import os
import urllib.request
import urllib.parse
def sendSlackMessage(message):
    print('Slack -- ' + message)
    req = urllib.request.Request(
        os.environ['SLACK_WEBHOOK'],
        json.dumps({'text': message}).encode('utf-8'),
        {'Content-Type': 'application/json'}
    )
    resp = urllib.request.urlopen(req)
    return resp.read()

def handler(event, context):
    # -- CloudWatch via Lambda
    try:
        msg = ':warning: *CloudWatch Alert* - {account} ({awsRegion}) - {eventSource} = *{eventName}* - {resource}'.format(
            account = event.get('account',''),
            eventSource = event.get('detail',{}).get('eventSource',''),
            eventName = event.get('detail',{}).get('eventName',''),
            awsRegion = event.get('detail',{}).get('awsRegion',''),
            resource = event.get('detail',{}).get('requestParameters',{}).get('groupId',''),
        )
        sendSlackMessage(msg)
    except:
        sendSlackMessage(json.dumps(event,indent=4))

    return {
        'statusCode': 200
    }