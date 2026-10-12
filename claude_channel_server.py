#!/usr/bin/env python3
"""Launch only the opted-in local stdio adapter; never launch Claude itself."""
from babel.claude_channel import main

if __name__ == "__main__":
    main()
