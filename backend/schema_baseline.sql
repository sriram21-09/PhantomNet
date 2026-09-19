CREATE TABLE alerts (
	id INTEGER NOT NULL, 
	timestamp DATETIME, 
	level VARCHAR, 
	type VARCHAR, 
	source_ip VARCHAR, 
	description VARCHAR, 
	details TEXT, 
	is_resolved BOOLEAN, 
	country VARCHAR, 
	city VARCHAR, 
	latitude FLOAT, 
	longitude FLOAT, 
	PRIMARY KEY (id)
);

CREATE TABLE attack_sessions (
	id INTEGER NOT NULL, 
	attacker_ip VARCHAR, 
	start_time DATETIME, 
	threat_score FLOAT, 
	PRIMARY KEY (id)
);

CREATE TABLE investigation_cases (
	id INTEGER NOT NULL, 
	title VARCHAR, 
	description TEXT, 
	status VARCHAR, 
	priority VARCHAR, 
	assigned_to VARCHAR, 
	created_at DATETIME, 
	updated_at DATETIME, 
	closed_at DATETIME, 
	PRIMARY KEY (id)
);

CREATE TABLE iocs (
	id INTEGER NOT NULL, 
	type VARCHAR, 
	value VARCHAR, 
	description VARCHAR, 
	threat_level VARCHAR, 
	is_watchlist BOOLEAN, 
	first_seen DATETIME, 
	last_seen DATETIME, 
	created_at DATETIME, 
	PRIMARY KEY (id)
);

CREATE TABLE packet_logs (
	id INTEGER NOT NULL, 
	timestamp DATETIME, 
	src_ip VARCHAR, 
	dst_ip VARCHAR, 
	src_port INTEGER, 
	dst_port INTEGER, 
	protocol VARCHAR, 
	length INTEGER, 
	attack_type VARCHAR, 
	threat_score FLOAT, 
	threat_level VARCHAR, 
	confidence FLOAT, 
	is_malicious BOOLEAN, 
	event VARCHAR, 
	anomaly_score FLOAT, 
	mail_from VARCHAR(256), 
	rcpt_to VARCHAR(256), 
	email_subject VARCHAR(512), 
	body_len INTEGER, 
	country VARCHAR, 
	city VARCHAR, 
	latitude FLOAT, 
	longitude FLOAT, 
	detected_signatures VARCHAR, 
	PRIMARY KEY (id)
);

CREATE TABLE policies (
	id INTEGER NOT NULL, 
	name VARCHAR, 
	description VARCHAR, 
	config VARCHAR, 
	created_at DATETIME, 
	PRIMARY KEY (id), 
	UNIQUE (name)
);

CREATE TABLE scheduled_reports (
	id INTEGER NOT NULL, 
	name VARCHAR, 
	template_type VARCHAR, 
	frequency VARCHAR, 
	schedule_time VARCHAR, 
	recipients VARCHAR, 
	filters TEXT, 
	day_of_week VARCHAR, 
	last_run DATETIME, 
	next_run DATETIME, 
	is_active BOOLEAN, 
	created_at DATETIME, 
	PRIMARY KEY (id)
);

CREATE TABLE search_history (
	id INTEGER NOT NULL, 
	query_json TEXT, 
	result_count INTEGER, 
	executed_at DATETIME, 
	analyst_name VARCHAR, 
	PRIMARY KEY (id)
);

CREATE TABLE sentinel_audit_logs (
	id INTEGER NOT NULL, 
	playbook_id VARCHAR(64), 
	action VARCHAR(64) NOT NULL, 
	user VARCHAR(128) NOT NULL, 
	details TEXT, 
	timestamp DATETIME NOT NULL, 
	PRIMARY KEY (id)
);

CREATE TABLE sentinel_playbooks (
	id INTEGER NOT NULL, 
	playbook_id VARCHAR(64) NOT NULL, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	version INTEGER NOT NULL, 
	parent_id INTEGER, 
	is_latest BOOLEAN NOT NULL, 
	regeneration_reason VARCHAR(512), 
	src_ip VARCHAR(45), 
	dst_port INTEGER, 
	protocol VARCHAR(16), 
	attack_type VARCHAR(128), 
	threat_score FLOAT, 
	confidence_score FLOAT, 
	quality_score FLOAT, 
	severity VARCHAR(16), 
	technique_id VARCHAR(32), 
	technique_name VARCHAR(256), 
	tactic VARCHAR(128), 
	mitre_url VARCHAR(512), 
	snort_rule TEXT, 
	sigma_rule TEXT, 
	playbook_name VARCHAR(256), 
	playbook_content TEXT, 
	template_name VARCHAR(128), 
	llm_narrative TEXT, 
	status VARCHAR(32) NOT NULL, 
	reviewed_by VARCHAR(128), 
	reviewed_at DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(parent_id) REFERENCES sentinel_playbooks (id) ON DELETE SET NULL
);

CREATE TABLE system_config (
	id INTEGER NOT NULL, 
	"key" VARCHAR, 
	value TEXT, 
	category VARCHAR, 
	sentinel_llm_enabled BOOLEAN, 
	updated_at DATETIME, 
	PRIMARY KEY (id)
);

CREATE TABLE traffic_stats (
	id INTEGER NOT NULL, 
	timestamp DATETIME, 
	total_packets INTEGER, 
	active_connections INTEGER, 
	PRIMARY KEY (id)
);

CREATE TABLE users (
	id INTEGER NOT NULL, 
	username VARCHAR, 
	email VARCHAR, 
	hashed_password VARCHAR, 
	role VARCHAR, 
	status VARCHAR, 
	last_login DATETIME, 
	created_at DATETIME, 
	PRIMARY KEY (id)
);

CREATE TABLE case_evidence (
	id INTEGER NOT NULL, 
	case_id INTEGER, 
	event_id INTEGER, 
	event_type VARCHAR, 
	notes TEXT, 
	added_at DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(case_id) REFERENCES investigation_cases (id)
);

CREATE TABLE events (
	id INTEGER NOT NULL, 
	session_id INTEGER, 
	source_ip VARCHAR, 
	src_port INTEGER, 
	honeypot_type VARCHAR, 
	raw_data VARCHAR, 
	timestamp DATETIME, 
	pcap_path VARCHAR, 
	country VARCHAR, 
	city VARCHAR, 
	latitude FLOAT, 
	longitude FLOAT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(session_id) REFERENCES attack_sessions (id)
);

CREATE TABLE honeypot_nodes (
	id INTEGER NOT NULL, 
	node_id VARCHAR, 
	hostname VARCHAR, 
	ip_address VARCHAR, 
	status VARCHAR, 
	last_seen DATETIME, 
	honeypot_type VARCHAR, 
	policy_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(policy_id) REFERENCES policies (id)
);

CREATE TABLE pcap_captures (
	id INTEGER NOT NULL, 
	event_id INTEGER, 
	file_path VARCHAR, 
	file_size INTEGER, 
	packet_count INTEGER, 
	protocol_summary TEXT, 
	capture_duration FLOAT, 
	analysis_status VARCHAR, 
	threat_patterns TEXT, 
	created_at DATETIME, 
	expires_at DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(event_id) REFERENCES events (id)
);

