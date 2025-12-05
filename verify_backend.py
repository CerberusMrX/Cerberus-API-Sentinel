import os
import sys
import django
from django.conf import settings

# Setup Django environment
sys.path.append('/home/cerberusmrxi/Desktop/new project/cerberus-sentinel/web/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

try:
    print("Attempting to import ScanExecutor...")
    from projects.scan_executor import ScanExecutor
    print("ScanExecutor imported successfully.")
    
    print("Attempting to initialize ScanExecutor...")
    executor = ScanExecutor()
    print(f"ScanExecutor initialized with {len(executor.scanners)} scanners.")
    
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
