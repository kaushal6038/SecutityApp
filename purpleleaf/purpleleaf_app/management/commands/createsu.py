from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

User = get_user_model()


class Command(BaseCommand):

    def handle(self, *args, **options):
        if not User.objects.filter(email="elliott@purpleleaf.io").exists():
            User.objects.create_superuser(name="elliott",email="elliott@purpleleaf.io", password="elliott@123")