BEGIN;

CREATE TABLE alembic_version (
    version_num VARCHAR(32) NOT NULL, 
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

-- Running upgrade  -> 0001_phase1

CREATE TABLE service_heartbeats (
    id SERIAL NOT NULL, 
    service_name VARCHAR(64) NOT NULL, 
    instance_id VARCHAR(128) NOT NULL, 
    status VARCHAR(32) NOT NULL, 
    service_metadata JSON NOT NULL, 
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    CONSTRAINT uq_service_heartbeat_identity UNIQUE (service_name, instance_id)
);

CREATE INDEX ix_service_heartbeats_last_seen_at ON service_heartbeats (last_seen_at);

INSERT INTO alembic_version (version_num) VALUES ('0001_phase1') RETURNING alembic_version.version_num;

-- Running upgrade 0001_phase1 -> 0002_phase2

CREATE TABLE runtime_events (
    event_id VARCHAR(64) NOT NULL, 
    docker_host_id VARCHAR(128) NOT NULL, 
    event_type VARCHAR(32) NOT NULL, 
    action VARCHAR(64) NOT NULL, 
    scope VARCHAR(64), 
    actor_id VARCHAR(128) NOT NULL, 
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    time_nano BIGINT NOT NULL, 
    container_id VARCHAR(128), 
    container_name VARCHAR(255), 
    image_id VARCHAR(128), 
    image_ref TEXT, 
    image_digest VARCHAR(255), 
    image_digest_status VARCHAR(32) NOT NULL, 
    command TEXT, 
    container_user VARCHAR(255), 
    attributes JSON NOT NULL, 
    container_snapshot JSON NOT NULL, 
    raw_event JSON NOT NULL, 
    received_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (event_id)
);

CREATE INDEX ix_runtime_events_occurred_at ON runtime_events (occurred_at);

CREATE INDEX ix_runtime_events_type_action ON runtime_events (event_type, action);

CREATE INDEX ix_runtime_events_container_id ON runtime_events (container_id);

CREATE INDEX ix_runtime_events_container_name ON runtime_events (container_name);

CREATE INDEX ix_runtime_events_image_digest ON runtime_events (image_digest);

CREATE INDEX ix_runtime_events_docker_host_time ON runtime_events (docker_host_id, time_nano);

CREATE TABLE image_identities (
    id SERIAL NOT NULL, 
    docker_host_id VARCHAR(128) NOT NULL, 
    image_id VARCHAR(128) NOT NULL, 
    image_ref TEXT, 
    primary_repo_digest VARCHAR(255), 
    repo_digests JSON NOT NULL, 
    repo_tags JSON NOT NULL, 
    os VARCHAR(64), 
    architecture VARCHAR(64), 
    digest_status VARCHAR(32) NOT NULL, 
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    CONSTRAINT uq_image_identity_host_image UNIQUE (docker_host_id, image_id)
);

CREATE INDEX ix_image_identities_primary_digest ON image_identities (primary_repo_digest);

CREATE INDEX ix_image_identities_last_seen_at ON image_identities (last_seen_at);

CREATE TABLE container_identities (
    id SERIAL NOT NULL, 
    docker_host_id VARCHAR(128) NOT NULL, 
    container_id VARCHAR(128) NOT NULL, 
    container_name VARCHAR(255), 
    image_id VARCHAR(128), 
    image_ref TEXT, 
    image_digest VARCHAR(255), 
    image_digest_status VARCHAR(32) NOT NULL, 
    current_snapshot JSON NOT NULL, 
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (id), 
    CONSTRAINT uq_container_identity_host_container UNIQUE (docker_host_id, container_id)
);

CREATE INDEX ix_container_identities_name ON container_identities (container_name);

CREATE INDEX ix_container_identities_image_digest ON container_identities (image_digest);

CREATE INDEX ix_container_identities_last_seen_at ON container_identities (last_seen_at);

UPDATE alembic_version SET version_num='0002_phase2' WHERE alembic_version.version_num = '0001_phase1';

-- Running upgrade 0002_phase2 -> 0003_phase3

CREATE TABLE process_exec_events (
    event_id VARCHAR(64) NOT NULL, 
    sensor_instance_id VARCHAR(128) NOT NULL, 
    sensor_hostname VARCHAR(255), 
    source VARCHAR(32) NOT NULL, 
    rule_name VARCHAR(255) NOT NULL, 
    priority VARCHAR(32) NOT NULL, 
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    time_nano BIGINT NOT NULL, 
    event_number BIGINT, 
    event_type VARCHAR(64) NOT NULL, 
    reported_docker_host_id VARCHAR(128), 
    reported_container_id VARCHAR(128), 
    docker_host_id VARCHAR(128), 
    container_id VARCHAR(128), 
    container_name VARCHAR(255), 
    image_id VARCHAR(128), 
    image_ref TEXT, 
    image_digest VARCHAR(255), 
    correlation_status VARCHAR(32) NOT NULL, 
    process_pid BIGINT NOT NULL, 
    process_ppid BIGINT, 
    process_vpid BIGINT, 
    process_name VARCHAR(255), 
    executable TEXT, 
    command_line TEXT, 
    working_directory TEXT, 
    tty BIGINT, 
    parent_name VARCHAR(255), 
    parent_executable TEXT, 
    parent_command_line TEXT, 
    parent_event_id VARCHAR(64), 
    user_uid BIGINT, 
    user_name VARCHAR(255), 
    group_gid BIGINT, 
    group_name VARCHAR(255), 
    tags JSON NOT NULL, 
    output TEXT, 
    output_fields JSON NOT NULL, 
    raw_event JSON NOT NULL, 
    received_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (event_id)
);

CREATE INDEX ix_process_exec_events_occurred_at ON process_exec_events (occurred_at);

CREATE INDEX ix_process_exec_events_container_time ON process_exec_events (container_id, time_nano);

CREATE INDEX ix_process_exec_events_reported_container ON process_exec_events (reported_container_id);

CREATE INDEX ix_process_exec_events_image_digest ON process_exec_events (image_digest);

CREATE INDEX ix_process_exec_events_process_name ON process_exec_events (process_name);

CREATE INDEX ix_process_exec_events_pid ON process_exec_events (docker_host_id, process_pid, occurred_at);

CREATE INDEX ix_process_exec_events_parent_event ON process_exec_events (parent_event_id);

CREATE INDEX ix_process_exec_events_correlation ON process_exec_events (correlation_status);

UPDATE alembic_version SET version_num='0003_phase3' WHERE alembic_version.version_num = '0002_phase2';

-- Running upgrade 0003_phase3 -> 0004_phase4

CREATE TABLE behavior_profiles (
    profile_id VARCHAR(36) NOT NULL, 
    image_digest VARCHAR(255) NOT NULL, 
    profile_version INTEGER NOT NULL, 
    status VARCHAR(16) NOT NULL, 
    feature_schema_version VARCHAR(64) NOT NULL, 
    model_hash VARCHAR(64) NOT NULL, 
    training_start TIMESTAMP WITH TIME ZONE NOT NULL, 
    training_end TIMESTAMP WITH TIME ZONE NOT NULL, 
    window_seconds INTEGER NOT NULL, 
    approved_by VARCHAR(128) NOT NULL, 
    approval_reference VARCHAR(255), 
    notes TEXT, 
    process_event_count INTEGER NOT NULL, 
    runtime_event_count INTEGER NOT NULL, 
    container_count INTEGER NOT NULL, 
    window_count INTEGER NOT NULL, 
    quality JSON NOT NULL, 
    training_manifest JSON NOT NULL, 
    features JSON NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    activated_at TIMESTAMP WITH TIME ZONE, 
    retired_at TIMESTAMP WITH TIME ZONE, 
    PRIMARY KEY (profile_id), 
    CONSTRAINT ck_behavior_profiles_version_positive CHECK (profile_version >= 1), 
    CONSTRAINT ck_behavior_profiles_window_positive CHECK (window_seconds >= 1), 
    CONSTRAINT ck_behavior_profiles_status CHECK (status IN ('draft', 'active', 'retired')), 
    CONSTRAINT uq_behavior_profiles_digest_version UNIQUE (image_digest, profile_version), 
    CONSTRAINT uq_behavior_profiles_digest_model_hash UNIQUE (image_digest, model_hash)
);

CREATE INDEX ix_behavior_profiles_image_digest ON behavior_profiles (image_digest);

CREATE INDEX ix_behavior_profiles_created_at ON behavior_profiles (created_at);

CREATE INDEX ix_behavior_profiles_status ON behavior_profiles (status);

CREATE UNIQUE INDEX uq_behavior_profiles_one_active_digest ON behavior_profiles (image_digest) WHERE status = 'active';

UPDATE alembic_version SET version_num='0004_phase4' WHERE alembic_version.version_num = '0003_phase3';

-- Running upgrade 0004_phase4 -> 0005_phase5

CREATE TABLE anomaly_scores (
    score_id VARCHAR(36) NOT NULL, 
    observation_key VARCHAR(64) NOT NULL, 
    profile_id VARCHAR(36) NOT NULL, 
    image_digest VARCHAR(255) NOT NULL, 
    profile_version INTEGER NOT NULL, 
    profile_model_hash VARCHAR(64) NOT NULL, 
    algorithm_version VARCHAR(64) NOT NULL, 
    status VARCHAR(32) NOT NULL, 
    score_band VARCHAR(32) NOT NULL, 
    total_score FLOAT, 
    window_start TIMESTAMP WITH TIME ZONE NOT NULL, 
    window_end TIMESTAMP WITH TIME ZONE NOT NULL, 
    window_seconds INTEGER NOT NULL, 
    process_event_count INTEGER NOT NULL, 
    runtime_event_count INTEGER NOT NULL, 
    container_count INTEGER NOT NULL, 
    components JSON NOT NULL, 
    explanation JSON NOT NULL, 
    observation_manifest JSON NOT NULL, 
    scoring_config JSON NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (score_id), 
    CONSTRAINT ck_anomaly_scores_status CHECK (status IN ('scored', 'insufficient_data')), 
    CONSTRAINT ck_anomaly_scores_band CHECK (score_band IN ('baseline_like', 'elevated', 'high', 'extreme', 'insufficient_data')), 
    CONSTRAINT ck_anomaly_scores_total_range CHECK (total_score IS NULL OR (total_score >= 0 AND total_score <= 1)), 
    CONSTRAINT ck_anomaly_scores_window_positive CHECK (window_seconds >= 1), 
    CONSTRAINT uq_anomaly_scores_observation_key UNIQUE (observation_key), 
    FOREIGN KEY(profile_id) REFERENCES behavior_profiles (profile_id) ON DELETE RESTRICT
);

CREATE INDEX ix_anomaly_scores_image_digest_window ON anomaly_scores (image_digest, window_start);

CREATE INDEX ix_anomaly_scores_profile_id ON anomaly_scores (profile_id);

CREATE INDEX ix_anomaly_scores_total_score ON anomaly_scores (total_score);

CREATE INDEX ix_anomaly_scores_created_at ON anomaly_scores (created_at);

CREATE INDEX ix_anomaly_scores_status ON anomaly_scores (status);

UPDATE alembic_version SET version_num='0005_phase5' WHERE alembic_version.version_num = '0004_phase4';

-- Running upgrade 0005_phase5 -> 0006_phase6

CREATE TABLE detection_allowlists (
    allowlist_id VARCHAR(36) NOT NULL, 
    matcher_hash VARCHAR(64) NOT NULL, 
    image_digest VARCHAR(255) NOT NULL, 
    rule_id VARCHAR(32) NOT NULL, 
    executable TEXT, 
    parent_executable TEXT, 
    reason TEXT NOT NULL, 
    approved_by VARCHAR(128) NOT NULL, 
    approval_reference VARCHAR(255), 
    active BOOLEAN NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    expires_at TIMESTAMP WITH TIME ZONE, 
    deactivated_at TIMESTAMP WITH TIME ZONE, 
    deactivated_by VARCHAR(128), 
    PRIMARY KEY (allowlist_id), 
    CONSTRAINT ck_detection_allowlists_rule_id CHECK (rule_id IN ('POR-DET-002', 'POR-DET-003', 'POR-DET-004'))
);

CREATE UNIQUE INDEX uq_detection_allowlists_active_matcher ON detection_allowlists (matcher_hash) WHERE active;

CREATE INDEX ix_detection_allowlists_digest_active ON detection_allowlists (image_digest, active);

CREATE INDEX ix_detection_allowlists_expires_at ON detection_allowlists (expires_at);

CREATE TABLE detection_runs (
    run_id VARCHAR(36) NOT NULL, 
    run_key VARCHAR(64) NOT NULL, 
    score_id VARCHAR(36) NOT NULL, 
    ruleset_version VARCHAR(64) NOT NULL, 
    ruleset_hash VARCHAR(64) NOT NULL, 
    allowlist_set_hash VARCHAR(64) NOT NULL, 
    applied_allowlist_ids JSON NOT NULL, 
    image_digest VARCHAR(255) NOT NULL, 
    window_start TIMESTAMP WITH TIME ZONE NOT NULL, 
    window_end TIMESTAMP WITH TIME ZONE NOT NULL, 
    status VARCHAR(32) NOT NULL, 
    matches_count INTEGER NOT NULL, 
    incident_created BOOLEAN NOT NULL, 
    result JSON NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (run_id), 
    CONSTRAINT ck_detection_runs_status CHECK (status IN ('insufficient_data', 'no_findings', 'findings_only', 'incident_created')), 
    CONSTRAINT uq_detection_runs_run_key UNIQUE (run_key), 
    CONSTRAINT uq_detection_runs_score_ruleset_allowlists UNIQUE (score_id, ruleset_version, allowlist_set_hash), 
    FOREIGN KEY(score_id) REFERENCES anomaly_scores (score_id) ON DELETE RESTRICT
);

CREATE INDEX ix_detection_runs_image_digest_window ON detection_runs (image_digest, window_start);

CREATE INDEX ix_detection_runs_created_at ON detection_runs (created_at);

CREATE INDEX ix_detection_runs_status ON detection_runs (status);

CREATE TABLE incidents (
    incident_id VARCHAR(36) NOT NULL, 
    detection_run_id VARCHAR(36) NOT NULL, 
    score_id VARCHAR(36) NOT NULL, 
    image_digest VARCHAR(255) NOT NULL, 
    title VARCHAR(255) NOT NULL, 
    status VARCHAR(32) NOT NULL, 
    anomaly_score FLOAT NOT NULL, 
    severity_score FLOAT NOT NULL, 
    severity_level VARCHAR(16) NOT NULL, 
    confidence_score FLOAT NOT NULL, 
    confidence_level VARCHAR(16) NOT NULL, 
    summary TEXT NOT NULL, 
    findings JSON NOT NULL, 
    container_ids JSON NOT NULL, 
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    acknowledged_at TIMESTAMP WITH TIME ZONE, 
    acknowledged_by VARCHAR(128), 
    closed_at TIMESTAMP WITH TIME ZONE, 
    closed_by VARCHAR(128), 
    closure_note TEXT, 
    PRIMARY KEY (incident_id), 
    CONSTRAINT ck_incidents_status CHECK (status IN ('open', 'acknowledged', 'resolved', 'dismissed')), 
    CONSTRAINT ck_incidents_severity_level CHECK (severity_level IN ('low', 'medium', 'high', 'critical')), 
    CONSTRAINT ck_incidents_confidence_level CHECK (confidence_level IN ('low', 'medium', 'high')), 
    CONSTRAINT ck_incidents_anomaly_range CHECK (anomaly_score >= 0 AND anomaly_score <= 1), 
    CONSTRAINT ck_incidents_severity_range CHECK (severity_score >= 0 AND severity_score <= 1), 
    CONSTRAINT ck_incidents_confidence_range CHECK (confidence_score >= 0 AND confidence_score <= 1), 
    CONSTRAINT uq_incidents_detection_run UNIQUE (detection_run_id), 
    FOREIGN KEY(detection_run_id) REFERENCES detection_runs (run_id) ON DELETE RESTRICT, 
    FOREIGN KEY(score_id) REFERENCES anomaly_scores (score_id) ON DELETE RESTRICT
);

CREATE INDEX ix_incidents_image_digest_first_seen ON incidents (image_digest, first_seen_at);

CREATE INDEX ix_incidents_status ON incidents (status);

CREATE INDEX ix_incidents_severity ON incidents (severity_score);

CREATE INDEX ix_incidents_created_at ON incidents (created_at);

CREATE TABLE incident_evidence (
    evidence_id VARCHAR(36) NOT NULL, 
    incident_id VARCHAR(36) NOT NULL, 
    sequence_no INTEGER NOT NULL, 
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    source_type VARCHAR(32) NOT NULL, 
    source_id VARCHAR(255) NOT NULL, 
    rule_id VARCHAR(32), 
    evidence_type VARCHAR(64) NOT NULL, 
    summary TEXT NOT NULL, 
    details JSON NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
    PRIMARY KEY (evidence_id), 
    CONSTRAINT uq_incident_evidence_sequence UNIQUE (incident_id, sequence_no), 
    FOREIGN KEY(incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
);

CREATE INDEX ix_incident_evidence_incident_time ON incident_evidence (incident_id, occurred_at);

CREATE INDEX ix_incident_evidence_source ON incident_evidence (source_type, source_id);

CREATE INDEX ix_incident_evidence_rule ON incident_evidence (rule_id);

UPDATE alembic_version SET version_num='0006_phase6' WHERE alembic_version.version_num = '0005_phase5';

COMMIT;

