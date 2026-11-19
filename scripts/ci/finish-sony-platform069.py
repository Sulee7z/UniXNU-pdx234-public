#!/usr/bin/env python3
"""Run the unmodified strict prelink with the additive069 source qualifier."""
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci'))
from platform069.overlays import run_inherited_main

if __name__=='__main__':run_inherited_main(Path(__file__).with_name('finish-d27-pac-abi.py'))
