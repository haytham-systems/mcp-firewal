-- MCP Firewall & Intent Guard — MySQL 8.0.16+ schema.
-- Loader contract: every statement ends with ";" at end of line; trigger bodies are single
-- statements, so no DELIMITER is needed (works with the mysql CLI and mysql2 multipleStatements).
-- Run the server with default_time_zone='+00:00'; all runtime SQL uses UTC_TIMESTAMP(3).

-- ─────────────────────────────────────────────────────────────────────────────
-- Identities
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fw_agents (
  id            VARCHAR(64)   NOT NULL,                 -- e.g. 'agent-research'
  display_name  VARCHAR(128)  NOT NULL,
  status        ENUM('active','disabled') NOT NULL DEFAULT 'active',
  api_key_hash  BINARY(32)    NOT NULL,                 -- SHA-256 of a 256-bit random key; key itself is never stored
  created_at    DATETIME(3)   NOT NULL DEFAULT (UTC_TIMESTAMP(3)),
  PRIMARY KEY (id),
  UNIQUE KEY uq_api_key (api_key_hash)
) ENGINE=InnoDB;

-- Human approvers hold Ed25519 private keys offline; only the public JWK lives here.
CREATE TABLE IF NOT EXISTS fw_approvers (
  id            VARCHAR(64)   NOT NULL,                 -- e.g. 'alice'
  display_name  VARCHAR(128)  NOT NULL,
  kid           VARCHAR(64)   NOT NULL,                 -- RFC 7638 thumbprint of public_jwk
  public_jwk    JSON          NOT NULL,
  status        ENUM('active','disabled') NOT NULL DEFAULT 'active',
  created_at    DATETIME(3)   NOT NULL DEFAULT (UTC_TIMESTAMP(3)),
  PRIMARY KEY (id),
  UNIQUE KEY uq_kid (kid)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS fw_approver_groups (
  group_id     VARCHAR(64) NOT NULL,                    -- e.g. 'dba', 'finance'
  approver_id  VARCHAR(64) NOT NULL,
  PRIMARY KEY (group_id, approver_id),
  KEY ix_approver (approver_id),
  CONSTRAINT fk_ag_approver FOREIGN KEY (approver_id) REFERENCES fw_approvers (id)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────────────────────
-- Tool classification: risk level + how to derive a resource id from arguments.
-- Unclassified tools are treated as 'destructive' with resource 'tool:<name>' (fail closed).
-- resource_template placeholders reference argument paths: 'github:repo/{owner}/{repo}'.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fw_tool_classes (
  id                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
  server_pattern     VARCHAR(128) NOT NULL,             -- glob, '*' = any server
  tool_pattern       VARCHAR(128) NOT NULL,             -- glob, e.g. 'github.delete_*'
  risk               ENUM('read','write','destructive') NOT NULL,
  resource_template  VARCHAR(512) NULL,
  description        VARCHAR(255) NULL,
  PRIMARY KEY (id),
  KEY ix_server (server_pattern)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────────────────────
-- Policies. Precedence is fixed and order-independent:
--   any matching 'deny'  >  any matching 'require_approval'  >  any matching 'allow'  >  default deny
-- A deny can therefore never be overridden by a later/higher allow (prompt-injection proof).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fw_policies (
  id                  INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name                VARCHAR(128) NOT NULL,
  agent_pattern       VARCHAR(64)  NOT NULL,            -- glob over fw_agents.id
  server_pattern      VARCHAR(128) NOT NULL,            -- glob over server id
  tool_pattern        VARCHAR(128) NOT NULL,            -- glob over tool name
  resource_pattern    VARCHAR(512) NOT NULL DEFAULT '**', -- segment glob: '*', 'prefix*', trailing '**'
  risk_levels         SET('read','write','destructive') NULL,  -- NULL = any risk
  effect              ENUM('allow','deny','require_approval') NOT NULL,
  required_approvals  TINYINT UNSIGNED NOT NULL DEFAULT 1,
  approver_group      VARCHAR(64)  NULL,                -- NULL = any active approver
  enabled             TINYINT(1)   NOT NULL DEFAULT 1,
  created_at          DATETIME(3)  NOT NULL DEFAULT (UTC_TIMESTAMP(3)),
  PRIMARY KEY (id),
  KEY ix_enabled (enabled),
  CONSTRAINT ck_approvals CHECK (required_approvals BETWEEN 1 AND 5)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────────────────────
-- Human-in-the-loop approvals. `challenge` is an HS256 JWT minted by the firewall that binds
-- agent/server/tool/resource/args_sha256/nonce; approvers sign SHA-256(challenge) with Ed25519.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fw_approvals (
  id                  CHAR(36)     NOT NULL,
  status              ENUM('pending','approved','denied','expired','consumed') NOT NULL DEFAULT 'pending',
  agent_id            VARCHAR(64)  NOT NULL,
  server_id           VARCHAR(128) NOT NULL,
  tool                VARCHAR(128) NOT NULL,
  resource            VARCHAR(512) NOT NULL,
  risk                ENUM('read','write','destructive') NOT NULL,
  args_sha256         BINARY(32)   NOT NULL,
  arguments           JSON         NOT NULL,            -- shown to the approver; purged after decision window
  challenge           TEXT         NOT NULL,
  policy_id           INT UNSIGNED NOT NULL,
  required_approvals  TINYINT UNSIGNED NOT NULL,
  approver_group      VARCHAR(64)  NULL,
  correlation_id      CHAR(36)     NOT NULL,
  created_at          DATETIME(3)  NOT NULL,
  expires_at          DATETIME(3)  NOT NULL,
  decided_at          DATETIME(3)  NULL,
  consumed_at         DATETIME(3)  NULL,
  PRIMARY KEY (id),
  KEY ix_status_exp (status, expires_at),
  KEY ix_match (agent_id, server_id, tool, args_sha256, status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS fw_approval_signatures (
  approval_id  CHAR(36)     NOT NULL,
  approver_id  VARCHAR(64)  NOT NULL,
  decision     ENUM('approve','deny') NOT NULL,
  signature    TEXT         NOT NULL,                   -- compact JWS (EdDSA), kept for non-repudiation
  signed_at    DATETIME(3)  NOT NULL,
  PRIMARY KEY (approval_id, approver_id),               -- one vote per approver
  CONSTRAINT fk_sig_approval FOREIGN KEY (approval_id) REFERENCES fw_approvals (id),
  CONSTRAINT fk_sig_approver FOREIGN KEY (approver_id) REFERENCES fw_approvers (id)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────────────────────
-- Tamper-evident audit log: SHA-256 hash chain (entry_hash = H(prev_hash || canonical(record))).
-- Appends serialize on fw_audit_head (SELECT ... FOR UPDATE), which also makes seq gap-free.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fw_audit_log (
  seq             BIGINT UNSIGNED NOT NULL,
  occurred_at     DATETIME(3)     NOT NULL,
  event_type      VARCHAR(48)     NOT NULL,
  correlation_id  CHAR(36)        NULL,
  agent_id        VARCHAR(64)     NULL,
  server_id       VARCHAR(128)    NULL,
  tool            VARCHAR(128)    NULL,
  resource        VARCHAR(512)    NULL,
  rpc_id          VARCHAR(128)    NULL,
  args_hmac       BINARY(32)      NULL,                 -- HMAC-SHA256(audit key, canonical args): linkable, not brute-forceable
  decision        VARCHAR(32)     NULL,
  reason_code     VARCHAR(64)     NULL,
  metadata        JSON            NOT NULL,
  prev_hash       BINARY(32)      NOT NULL,
  entry_hash      BINARY(32)      NOT NULL,
  PRIMARY KEY (seq),
  KEY ix_corr (correlation_id),
  KEY ix_agent_time (agent_id, occurred_at),
  KEY ix_tool_time (tool, occurred_at),
  KEY ix_decision_time (decision, occurred_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS fw_audit_head (
  id         TINYINT UNSIGNED NOT NULL,
  last_seq   BIGINT UNSIGNED  NOT NULL,
  last_hash  BINARY(32)       NOT NULL,
  PRIMARY KEY (id),
  CONSTRAINT ck_singleton CHECK (id = 1)
) ENGINE=InnoDB;

INSERT IGNORE INTO fw_audit_head (id, last_seq, last_hash) VALUES (1, 0, UNHEX(REPEAT('00', 32)));

DROP TRIGGER IF EXISTS trg_fw_audit_no_update;
DROP TRIGGER IF EXISTS trg_fw_audit_no_delete;
CREATE TRIGGER trg_fw_audit_no_update BEFORE UPDATE ON fw_audit_log FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fw_audit_log is append-only';
CREATE TRIGGER trg_fw_audit_no_delete BEFORE DELETE ON fw_audit_log FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fw_audit_log is append-only';
