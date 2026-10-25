"""Render the real terminal recording as a readable 1080p MP4 using Pillow/FFmpeg."""
import json
from pathlib import Path
import subprocess
import textwrap

from PIL import Image, ImageDraw, ImageFont

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'artifacts/local/college-submission/recording'
FONT='/usr/share/fonts/TTF/DejaVuSansMono.ttf'
SANS='/usr/share/fonts/TTF/DejaVuSans.ttf'


def render():
    meta=json.loads((OUT/'run-metadata.json').read_text())
    if meta['exit_code']!=0: raise SystemExit('A successful captured run is required.')
    metrics=json.loads((OUT/'metrics.json').read_text())
    events=[json.loads(line) for line in (OUT/'demo.cast').read_text().splitlines()[1:]]
    passes=[(t,s.strip()) for t,kind,s in events if kind=='o' and '[PASS]' in s]
    if len(passes)<20: raise SystemExit('Incomplete demonstration recording')
    # Keep the authentic pass messages in original order; combine pairs for readability.
    groups=[passes[i:i+2] for i in range(0,len(passes),2)]
    frames=OUT/'frames';frames.mkdir(exist_ok=True)
    mono=ImageFont.truetype(FONT,27);small=ImageFont.truetype(SANS,24)
    title=ImageFont.truetype(SANS,44);large=ImageFont.truetype(SANS,33)
    history=[];paths=[]
    for i,group in enumerate(groups):
        im=Image.new('RGB',(1920,1080),'#09121c');d=ImageDraw.Draw(im)
        d.text((96,65),'PORYGON',font=title,fill='#edf5fa')
        d.text((96,127),'Container runtime security · working demonstration',font=large,fill='#a9bfd1')
        d.text((96,191),'Anurup R Krishnan  |  cb.sc.u4cse23559',font=small,fill='#829bae')
        d.rounded_rectangle((80,260,1840,900),radius=18,fill='#101f2b',outline='#2a4051',width=2)
        d.text((112,282),'$ bash scripts/submission/run_demo.sh',font=mono,fill='#82d9bf')
        d.line((112,332,1808,332),fill='#2a4051',width=2)
        for timestamp,line in group:
            history.extend(textwrap.wrap(line,width=100,subsequent_indent='       '))
        for j,line in enumerate(history[-13:]):
            d.text((112,362+j*38),line,font=mono,fill='#dce9f2' if j<len(history[-13:])-2 else '#8fe3c6')
        timestamp=group[-1][0]
        d.text((96,935),f'Captured run time {int(timestamp)//60:02d}:{int(timestamp)%60:02d}  ·  idle waits condensed',font=small,fill='#829bae')
        d.rectangle((96,1008,1824,1014),fill='#233645')
        d.rectangle((96,1008,96+int(1728*(i+1)/(len(groups)+1)),1014),fill='#70d7b1')
        path=frames/f'frame-{i:03d}.png';im.save(path);paths.append((path,4.0))
    im=Image.new('RGB',(1920,1080),'#09121c');d=ImageDraw.Draw(im)
    d.text((96,75),'MEASURED RUN RESULTS',font=title,fill='#edf5fa')
    lines=[f"Process records: {metrics['persisted_process_records']} / {metrics['observed_falco_records']} observed",
           f"Duplicate rows after replay: {metrics['additional_rows_after_replay']}",
           f"Baseline score: {metrics['baseline_score']:.4f}",
           f"Novel workload score: {metrics['novel_score']:.4f}",
           f"Incident created: {metrics['incident_created']}   Findings: {metrics['matched_findings']}",
           f"Approved containment: {metrics['containment_status']}",
           f"Rollback: {metrics['rollback_status']}   Running: {metrics['running_after_rollback']}"]
    for j,line in enumerate(lines):d.text((110,230+j*86),line,font=large,fill='#8fe3c6')
    d.text((110,925),'Source: metrics.json + timestamped demo.cast + sample-outputs/',font=small,fill='#a9bfd1')
    last=frames/'results.png';im.save(last);paths.append((last,10.0))
    playlist=OUT/'video-frames.txt'
    playlist.write_text(''.join(f"file '{p.resolve()}'\nduration {duration}\n" for p,duration in paths)+f"file '{last.resolve()}'\n")
    subprocess.run(['ffmpeg','-y','-hide_banner','-loglevel','error','-f','concat','-safe','0','-i',str(playlist),
                    '-vf','fps=24,format=yuv420p','-c:v','libx264','-preset','fast','-crf','20',
                    '-movflags','+faststart',str(OUT/'demo.mp4')],check=True)
    print(OUT/'demo.mp4')


if __name__=='__main__':render()
