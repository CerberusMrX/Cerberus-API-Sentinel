# Scan Hang Analysis

## Progress Calculation
With 23 scanners and formula `15 + int((i / 23) * 70)`:
- Scanner 0: 15%
- Scanner 1: 18%
- Scanner  2: 21%
- **Scanner 3: 24% ← HANG OCCURS HERE**
- Scanner 4: 27%

## Scanner at 24% Progress
**Index 3 = SSRFScanner**

## Root Cause

The SSRF scanner makes requests to external URLs and callback servers which can:
1. Take a very long time to timeout
2. Hang indefinitely if the target doesn't respond
3. Get blocked by firewalls causing long waits

Even though individual HTTP requests have timeouts (3-10s), the scanner as a whole has no timeout limit, so if it makes many requests, it can accumulate time.

## Solution
Add a per-scanner timeout wrapper in scan_executor.py to ensure no single scanner runs longer than 30 seconds.
