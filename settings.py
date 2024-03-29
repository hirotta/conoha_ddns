import os
from os.path import join, dirname
from dotenv import load_dotenv

load_dotenv(verbose=True)

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

USERNAME = os.environ.get("USERNAME")
PASSWORD = os.environ.get("PASSWORD")
TENANT_ID = os.environ.get("TENANT_ID")
TARGET_DOMAIN = os.environ.get("TARGET_DOMAIN")
TARGET_RECORD = os.environ.get("TARGET_RECORD")
