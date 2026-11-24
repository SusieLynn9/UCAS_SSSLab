#!/usr/bin/env python3
"""Build the exact Lab 1A ZIP layout after the report and video are supplied."""
import argparse
from pathlib import Path
import re
import zipfile
from urllib.parse import urlparse

ROOT=Path(__file__).resolve().parents[1]


def package(name,student_id,repo_url,report,video,output):
    if not name or len(name)>80 or re.search(r'[/\\\x00-\x1f:]',name) or name in ('.','..'):
        raise ValueError('姓名不可为空或包含路径/控制字符')
    if not re.fullmatch(r'[0-9]{6,30}',student_id):raise ValueError('请输入真实学号（6-30 位数字）')
    url=urlparse(repo_url)
    if url.scheme!='https' or url.hostname not in ('github.com','gitee.com','gitlab.com') or len(url.path.strip('/').split('/'))<2:
        raise ValueError('需要真实的 GitHub/Gitee/GitLab HTTPS 仓库地址，并在报告正文中写入此链接')
    report,video,output=Path(report),Path(video),Path(output)
    for path in (report,video):
        if not path.is_file():raise FileNotFoundError(path)
    if report.suffix.lower() not in ('.pdf','.docx'):raise ValueError('报告必须为 PDF 或 DOCX')
    if video.suffix.lower()!='.mp4':raise ValueError('演示必须为 MP4')
    if report.suffix.lower()=='.pdf' and report.read_bytes()[:5]!=b'%PDF-':raise ValueError('报告不是有效的 PDF 文件')
    with video.open('rb') as f:header=f.read(4096)
    if b'ftyp' not in header:raise ValueError('视频缺少 MP4 ftyp 文件标记')
    folder=f'{name}_{student_id}_EX1A';prefix=f'{name}_{student_id}_ex1A'
    output.mkdir(parents=True,exist_ok=True);target=output/(folder+'.zip')
    if target.exists():raise FileExistsError(f'拒绝覆盖已有提交包：{target}')
    with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
        z.write(report,f'{folder}/{prefix}_report{report.suffix.lower()}');z.write(video,f'{folder}/{prefix}_play.mp4')
        source=f'{folder}/{prefix}_src/'
        paths=[ROOT/'run.py',ROOT/'launch.command',ROOT/'verify_live.command',ROOT/'README.md']
        for directory in ('sniffer','scripts','tests','samples'):
            paths.extend(p for p in (ROOT/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts and not p.name.endswith(('.pyc','.DS_Store')))
        for p in paths:z.write(p,source+p.relative_to(ROOT).as_posix())
    return target


def main():
    p=argparse.ArgumentParser(description='按课程命名规范生成未加密 ZIP；不生成虚假的报告或视频')
    p.add_argument('--name',required=True);p.add_argument('--student-id',required=True);p.add_argument('--repo-url',required=True);p.add_argument('--report',required=True);p.add_argument('--video',required=True);p.add_argument('--output',default='output/submission')
    args=p.parse_args()
    try:print(package(args.name,args.student_id,args.repo_url,args.report,args.video,args.output))
    except (ValueError,OSError) as e:p.exit(1,str(e)+'\n')
if __name__=='__main__':main()
