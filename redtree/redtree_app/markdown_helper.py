from .models import *
import re
from utils.MediaUploader import MediaUploader


def find_markdown_images(markdown_text):
    regex = r"[^(\s]+\.(?:jpeg|jpg|png|gif)(?=\))"
    return re.findall(regex, markdown_text)


def change_media_path(markdown_text):
    regex = r"[^(\s]+(?=\))"
    markdown_images = re.findall(regex, markdown_text)
    for image in markdown_images:
        if image.startswith('http'):
            image_name = image.split('?')[0].split('/')[-1]
            image_key = ''.join(['screenshots/', image_name])
        else:
            image_key = ''.join(['screenshots/', os.path.basename(image)])
        markdown_text = markdown_text.replace(image,image_key)
    return markdown_text
 

def get_markdown_with_images(markdown_text):
	if markdown_text:
		regex = r"[^(\s]+\.(?:jpeg|jpg|png|gif)(?=\))"
		markdown_images = re.findall(regex, markdown_text)
		from redtree_app.models import ClientConfiguration
		for image in markdown_images:
			client_conf_obj = ClientConfiguration.objects.first()
			if client_conf_obj and client_conf_obj.storage_type=="S3":
				image_key = ''.join(['screenshots/', os.path.basename(image)])
				media_uploader = MediaUploader(client_conf_obj, image_key)
				s3_image_link = media_uploader.get_link()
				markdown_text = re.sub(image, s3_image_link, markdown_text)
			else:
				actual_file_path = ''.join(['/media/', image])
				markdown_text = re.sub(image, actual_file_path, markdown_text)
		return markdown_text
