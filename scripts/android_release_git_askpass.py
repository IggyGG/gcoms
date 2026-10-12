#!/usr/bin/env python3
"""Git's private credential pipe; never place the token in a remote URL."""
import os
from pathlib import Path
import sys

if 'username' in sys.argv[1].lower():
    print('ghost-android-release')
elif 'password' in sys.argv[1].lower():
    print(Path(os.environ['ANDROID_FORGEJO_TOKEN_FILE']).read_text().strip())
else:
    raise SystemExit('unexpected Git credential prompt')
