import json
from scanner.collector import collector
import boto3
from datetime import datetime

def save_s3(contents):

    AWS_BUCKET_NAME = 'awssecurityinfo-reports' # -- make this a parameter
    
    # write the data
    account = contents['sts']['get_caller_identity']['Account']
    timestampStr = datetime.now().strftime("%Y/%m/%d")
    key =  timestampStr + '/' + str(account) + '.json'

    s3 = boto3.resource('s3')
	bucket = s3.Bucket(AWS_BUCKET_NAME)
	
	# -- save the json file
	bucket.put_object(
		ACL = 'bucket-owner-full-control',
		ContentType='application/json',
		Key=key,
		Body=json.dumps(contents, indent=4, sort_keys=True, default=convert_timestamp)
	)

# == connect directly - assume lambda has all the access
def connect_direct():
    c = collector(None,None,None)
    c.collect_all()
    #c.write_json(args.json)    # TODO - make it s3

    save_s3(c.cache)
    
def lambda_handler(event, context):
    
    connect_direct()
    
    
    # TODO implement
    return {
        'statusCode': 200,
        'body': json.dumps('Hello whatever!')
    }
