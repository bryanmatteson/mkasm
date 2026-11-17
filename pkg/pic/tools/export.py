#!/usr/bin/env python3
"""Reproduce constructors.json from a Ghidra 12.1.2 installation."""
import argparse,os,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--ghidra',type=Path,default=Path.home()/'Ghidra');p.add_argument('--artifacts',type=Path,required=True);args=p.parse_args()
args.artifacts.mkdir(parents=True,exist_ok=True)
cp=os.pathsep.join(map(str,sorted((args.ghidra/'Ghidra').rglob('*.jar'))))
source=Path(__file__).with_name('ExportPIC.java')
subprocess.run(['javac','-proc:none','-cp',cp,'-d',str(args.artifacts),str(source)],check=True)
with (source.parent.parent/'data/constructors.json').open('w') as out:
 subprocess.run(['java','-Djava.awt.headless=true','-cp',str(args.artifacts)+os.pathsep+cp,'ExportPIC',str(args.ghidra)],stdout=out,check=True)
