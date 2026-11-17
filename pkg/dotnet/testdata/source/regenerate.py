#!/usr/bin/env python3
"""Rebuild original fixtures and independent PEReader expectations using .NET 10.0.401.
Run from this directory: python3 regenerate.py <artifact directory> [dotnet path].
"""
import pathlib, shutil, subprocess, sys
source=pathlib.Path(__file__).resolve().parent
destination=source.parent
artifact=pathlib.Path(sys.argv[1]).expanduser().resolve()
dotnet=sys.argv[2] if len(sys.argv)>2 else 'dotnet'
artifact.mkdir(parents=True,exist_ok=True)
shutil.copy2(source/'global.json',artifact/'global.json')
for project,files in [('fixture',['Fixture.cs','Fixture.csproj','payload.txt']),('oracle',['Oracle.cs','Oracle.csproj'])]:
 (artifact/project).mkdir(exist_ok=True)
 for name in files: shutil.copy2(source/name,artifact/project/name)
subprocess.run([dotnet,'build',str(artifact/'oracle/Oracle.csproj'),'-c','Release','--nologo'],cwd=artifact,check=True)
for name,platform,ext in [('anycpu','AnyCPU','.dll'),('x86','x86','.exe'),('x64','x64','.dll'),('embedded','AnyCPU','.dll')]:
 subprocess.run([dotnet,'build',str(artifact/'fixture/Fixture.csproj'),'-t:Rebuild','-c','Release','-p:PlatformTarget='+platform,'-p:TargetExt='+ext,'-p:DebugType='+('embedded'if name=='embedded'else'portable'),'-o',str(artifact/name),'--nologo'],cwd=artifact,check=True)
 shutil.copy2(artifact/name/('ManagedFixture'+ext),destination/(name+ext))
 if name!='embedded': shutil.copy2(artifact/name/'ManagedFixture.pdb',destination/(name+'.pdb'))
for file in sorted(destination.iterdir()):
 if file.suffix in ['.dll','.exe','.pdb']:
  result=subprocess.run([dotnet,str(artifact/'oracle/bin/Release/net10.0/Oracle.dll'),str(file)],cwd=artifact,capture_output=True,check=True)
  file.with_suffix(file.suffix+'.json').write_bytes(result.stdout)
