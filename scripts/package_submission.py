#!/usr/bin/env python3
"""Package Lab 1B without runtime keys, user data, local notes or Git internals."""
import argparse,json,re,zipfile
from pathlib import Path
from urllib.parse import urlparse
ROOT=Path(__file__).resolve().parents[1]

def package(name,student_id,repo_url,report,video,output):
    if not name or re.search(r'[/\\\x00-\x1f:]',name) or name in ('.','..'):raise ValueError('Invalid student name')
    if not re.fullmatch('[0-9]{6,30}',student_id):raise ValueError('Invalid student ID')
    u=urlparse(repo_url)
    if u.scheme!='https' or u.hostname not in ('github.com','gitee.com','gitlab.com') or len(u.path.strip('/').split('/'))<2:raise ValueError('A real repository URL is required')
    report,video,output=map(Path,(report,video,output))
    if not report.is_file() or not video.is_file():raise FileNotFoundError('Report and real MP4 video are required')
    if report.suffix.lower() not in ('.pdf','.docx') or video.suffix.lower()!='.mp4':raise ValueError('Expected PDF/DOCX report and MP4 video')
    with video.open('rb') as f:
        if b'ftyp' not in f.read(4096):raise ValueError('Invalid MP4 header')
    if report.suffix.lower()=='.pdf':
        with report.open('rb') as f:
            if f.read(5)!=b'%PDF-':raise ValueError('Invalid PDF header')
    folder=f'{name}_{student_id}_EX1B';prefix=f'{name}_{student_id}_ex1B';output.mkdir(parents=True,exist_ok=True);target=output/(folder+'.zip')
    if target.exists():raise FileExistsError('Refusing to overwrite '+str(target))
    roots=['run_server.py','run_client.py','client_cli.py','setup_demo.command','launch_server.command','launch_server_sandboxed.command','launch_client.command','.gitignore','requirements-report.txt']
    files=[ROOT/n for n in roots if (ROOT/n).is_file()]
    for directory in ('harbor','scripts','tests','evidence'):
        files.extend(p for p in (ROOT/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.pyc','.pem','.key','.p12') and p.name!='.DS_Store')
    with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
        z.write(report,f'{folder}/{prefix}_report{report.suffix.lower()}');z.write(video,f'{folder}/{prefix}_play.mp4')
        for path in files:z.write(path,f'{folder}/{prefix}_src/'+path.relative_to(ROOT).as_posix())
        z.writestr(f'{folder}/{prefix}_src/submission.json',json.dumps({'name':name,'student_id':student_id,'repository':repo_url,'lab':'1B','setup':'Run setup_demo.command to generate your own local certificates; no private keys are included.'},ensure_ascii=False,indent=2))
    return target

def main():
    p=argparse.ArgumentParser();p.add_argument('--name',default='刘爽');p.add_argument('--student-id',default='202628013229057');p.add_argument('--repo-url',default='https://github.com/SusieLynn9/UCAS_SSSLab');p.add_argument('--report',type=Path,default=ROOT/'output/pdf/刘爽_202628013229057_ex1B_report.pdf');p.add_argument('--video',type=Path,required=True);p.add_argument('--output',type=Path,default=ROOT/'output/submission');a=p.parse_args()
    try:print(package(a.name,a.student_id,a.repo_url,a.report,a.video,a.output))
    except (OSError,ValueError) as e:p.exit(1,str(e)+'\n')
if __name__=='__main__':main()
