"""Regenerate measured demo metrics from acceptance artifacts."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'artifacts/local/college-submission/recording'


def collect():
    OUT.mkdir(parents=True,exist_ok=True)
    def read(name): return json.loads((ROOT/'artifacts'/name).read_text())
    integrity=read('ebpf-capture-integrity.json')
    normal=read('scoring-normal-score.json');novel=read('scoring-novel-score.json')
    detection=read('detection-novel-detection.json')
    execution=read('containment-execution.json');rollback=read('containment-rolled-back-execution.json')
    metrics={'schema_version':'porygon.demo.metrics.v1','capture_run_id':integrity['run_id'],
      'observed_falco_records':integrity['boundaries']['falco_file_probe_records_observed'],
      'persisted_process_records':integrity['boundaries']['postgres_probe_rows_after_recovery'],
      'additional_rows_after_replay':integrity['boundaries']['postgres_row_growth_after_replay'],
      'baseline_score':normal['total_score'],'novel_score':novel['total_score'],
      'score_window_seconds':novel['window_seconds'],'incident_created':detection['run']['incident_created'],
      'matched_findings':detection['run']['matches_count'],
      'containment_status':execution['status'],'paused_after_action':execution['post_state']['paused'],
      'rollback_status':rollback['status'],'running_after_rollback':rollback['post_state']['running']}
    assert metrics['observed_falco_records']==metrics['persisted_process_records']
    assert metrics['additional_rows_after_replay']==0
    assert metrics['novel_score']>metrics['baseline_score']
    assert metrics['incident_created'] and metrics['paused_after_action'] and metrics['running_after_rollback']
    assert metrics['containment_status']=='succeeded' and metrics['rollback_status']=='rolled_back'
    (OUT/'metrics.json').write_text(json.dumps(metrics,indent=2)+'\n')
    versions={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
      'kernel':subprocess.check_output(['uname','-r'],text=True).strip(),
      'scoring_algorithm':novel['algorithm_version'],'profile_version':novel['profile_version'],
      'profile_model_hash':novel['profile_model_hash'],'image_digest':novel['image_digest'],
      'ruleset_version':detection['run']['ruleset_version'],'ruleset_hash':detection['run']['ruleset_hash'],
      'falco_image':'falcosecurity/falco:0.45.1@sha256:69e957f91b3a6beb5c82e2afae33ec3e4479dab2d4421475d288d0cd113cedf6',
      'compose_sha256':hashlib.sha256((ROOT/'compose.yaml').read_bytes()).hexdigest()}
    (OUT/'versions.json').write_text(json.dumps(versions,indent=2)+'\n')
    print(json.dumps(metrics,indent=2))


if __name__=='__main__':collect()
