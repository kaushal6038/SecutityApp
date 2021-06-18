import boto3


class MediaUploader:
    def __init__(self, client_conf_obj, key, image=None):
        self.client_s3 = boto3.client(
            's3',
            aws_access_key_id=client_conf_obj.s3_access_token,
            aws_secret_access_key=client_conf_obj.s3_secret_access_token,
            region_name='us-east-1'
        )
        self.client_conf_obj = client_conf_obj
        self.image = image
        self.key = key

    def upload(self):
        try:
            self.client_s3.upload_fileobj(self.image, self.client_conf_obj.s3_bucket_name, self.key,
                                          ExtraArgs={"ACL": "private"})
            return "success"
        except:
            pass
            
    def get_link(self):
        try:
            url = self.client_s3.generate_presigned_url('get_object',
                                                        ExpiresIn=60,
                                                        Params={'Bucket': self.client_conf_obj.s3_bucket_name,
                                                                'Key': self.key})
            return url
        except:
            pass
