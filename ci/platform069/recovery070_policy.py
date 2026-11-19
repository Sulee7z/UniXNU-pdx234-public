"""Retain the unmodified PDX069 launch policy alongside the PDX070 BootLog."""
from platform069.crashes.qualify import adapt_launch_policy

ADAPTERS = {'crashes069-official-launch-policy': adapt_launch_policy}
