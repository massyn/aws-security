import boto3

# enable encryption on all S3 buckets
def remediate_s3_encryption(ACCESS_KEY = None,SECRET_KEY = None,SESSION_TOKEN = None):
    client = boto3.client('s3',
        aws_access_key_id		= ACCESS_KEY,
        aws_secret_access_key	= SECRET_KEY,
        aws_session_token		= SESSION_TOKEN
    )

    for bucket in client.list_buckets()['Buckets']:
        bucketname = bucket.get('Name')
        print(' - ' + bucketname)
        try:
            e = client.get_bucket_encryption(Bucket = bucketname).get('ServerSideEncryptionConfiguration')['Rules']
        except:
            e = []

        is_enabled = False
        for r in e:
            if r['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] != '':
                is_enabled = True
                
        if not is_enabled:
            print(' ** REMEDIATE ========')
            response = client.put_bucket_encryption(
                Bucket = bucketname,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'   # if the default AES256 encryption is not sufficient, you need to adjust this part.  See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.put_bucket_encryption for more info
                        }
                    },
                    ]
                }
            )
            print(response)



if __name__ == "__main__":
    remediate_s3_encryption()