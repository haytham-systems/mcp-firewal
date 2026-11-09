'use strict';

const { DataTypes, literal } = require('sequelize');

const binary32 = 'BINARY(32)';
const utcNow = literal('UTC_TIMESTAMP(3)');
const schemaTables = [
  'fw_agents',
  'fw_approvers',
  'fw_approver_groups',
  'fw_tool_classes',
  'fw_policies',
  'fw_approvals',
  'fw_approval_signatures',
  'fw_audit_log',
  'fw_audit_head',
];

const createAuditTriggers = async (sequelize, existing = new Set()) => {
  if (!existing.has('trg_fw_audit_no_update')) {
    await sequelize.query(
      "CREATE TRIGGER `trg_fw_audit_no_update` BEFORE UPDATE ON `fw_audit_log` FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fw_audit_log is append-only'",
    );
  }
  if (!existing.has('trg_fw_audit_no_delete')) {
    await sequelize.query(
      "CREATE TRIGGER `trg_fw_audit_no_delete` BEFORE DELETE ON `fw_audit_log` FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fw_audit_log is append-only'",
    );
  }
};

module.exports = {
  async up(queryInterface) {
    const [existingTables] = await queryInterface.sequelize.query(
      'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()',
    );
    const existing = new Set(existingTables.map(({ TABLE_NAME }) => TABLE_NAME));
    const existingSchemaTables = schemaTables.filter((table) => existing.has(table));
    if (existingSchemaTables.length > 0) {
      if (existingSchemaTables.length !== schemaTables.length) {
        throw new Error(
          `Partial firewall schema found (${existingSchemaTables.join(', ')}); refusing to apply initial migration over existing tables`,
        );
      }
      const [triggers] = await queryInterface.sequelize.query(
        "SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE() AND TRIGGER_NAME IN ('trg_fw_audit_no_update', 'trg_fw_audit_no_delete')",
      );
      await createAuditTriggers(queryInterface.sequelize, new Set(triggers.map(({ TRIGGER_NAME }) => TRIGGER_NAME)));
      return;
    }

    await queryInterface.createTable('fw_agents', {
      id: { type: DataTypes.STRING(64), allowNull: false, primaryKey: true },
      display_name: { type: DataTypes.STRING(128), allowNull: false },
      status: { type: DataTypes.ENUM('active', 'disabled'), allowNull: false, defaultValue: 'active' },
      api_key_hash: { type: binary32, allowNull: false },
      created_at: { type: DataTypes.DATE(3), allowNull: false, defaultValue: utcNow },
    });
    await queryInterface.addIndex('fw_agents', ['api_key_hash'], { name: 'uq_api_key', unique: true });

    await queryInterface.createTable('fw_approvers', {
      id: { type: DataTypes.STRING(64), allowNull: false, primaryKey: true },
      display_name: { type: DataTypes.STRING(128), allowNull: false },
      kid: { type: DataTypes.STRING(64), allowNull: false },
      public_jwk: { type: DataTypes.JSON, allowNull: false },
      status: { type: DataTypes.ENUM('active', 'disabled'), allowNull: false, defaultValue: 'active' },
      created_at: { type: DataTypes.DATE(3), allowNull: false, defaultValue: utcNow },
    });
    await queryInterface.addIndex('fw_approvers', ['kid'], { name: 'uq_kid', unique: true });

    await queryInterface.createTable('fw_approver_groups', {
      group_id: { type: DataTypes.STRING(64), allowNull: false, primaryKey: true },
      approver_id: { type: DataTypes.STRING(64), allowNull: false, primaryKey: true },
    });
    await queryInterface.addIndex('fw_approver_groups', ['approver_id'], { name: 'ix_approver' });
    await queryInterface.addConstraint('fw_approver_groups', {
      fields: ['approver_id'],
      type: 'foreign key',
      name: 'fk_ag_approver',
      references: { table: 'fw_approvers', field: 'id' },
    });

    await queryInterface.createTable('fw_tool_classes', {
      id: { type: DataTypes.INTEGER.UNSIGNED, allowNull: false, autoIncrement: true, primaryKey: true },
      server_pattern: { type: DataTypes.STRING(128), allowNull: false },
      tool_pattern: { type: DataTypes.STRING(128), allowNull: false },
      risk: { type: DataTypes.ENUM('read', 'write', 'destructive'), allowNull: false },
      resource_template: { type: DataTypes.STRING(512), allowNull: true },
      description: { type: DataTypes.STRING(255), allowNull: true },
    });
    await queryInterface.addIndex('fw_tool_classes', ['server_pattern'], { name: 'ix_server' });

    await queryInterface.createTable('fw_policies', {
      id: { type: DataTypes.INTEGER.UNSIGNED, allowNull: false, autoIncrement: true, primaryKey: true },
      name: { type: DataTypes.STRING(128), allowNull: false },
      agent_pattern: { type: DataTypes.STRING(64), allowNull: false },
      server_pattern: { type: DataTypes.STRING(128), allowNull: false },
      tool_pattern: { type: DataTypes.STRING(128), allowNull: false },
      resource_pattern: { type: DataTypes.STRING(512), allowNull: false, defaultValue: '**' },
      risk_levels: { type: DataTypes.SET('read', 'write', 'destructive'), allowNull: true },
      effect: { type: DataTypes.ENUM('allow', 'deny', 'require_approval'), allowNull: false },
      required_approvals: { type: DataTypes.TINYINT.UNSIGNED, allowNull: false, defaultValue: 1 },
      approver_group: { type: DataTypes.STRING(64), allowNull: true },
      enabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
      created_at: { type: DataTypes.DATE(3), allowNull: false, defaultValue: utcNow },
    });
    await queryInterface.addIndex('fw_policies', ['enabled'], { name: 'ix_enabled' });
    await queryInterface.sequelize.query(
      'ALTER TABLE `fw_policies` ADD CONSTRAINT `ck_approvals` CHECK (`required_approvals` BETWEEN 1 AND 5)',
    );

    await queryInterface.createTable('fw_approvals', {
      id: { type: DataTypes.CHAR(36), allowNull: false, primaryKey: true },
      status: {
        type: DataTypes.ENUM('pending', 'approved', 'denied', 'expired', 'consumed'),
        allowNull: false,
        defaultValue: 'pending',
      },
      agent_id: { type: DataTypes.STRING(64), allowNull: false },
      server_id: { type: DataTypes.STRING(128), allowNull: false },
      tool: { type: DataTypes.STRING(128), allowNull: false },
      resource: { type: DataTypes.STRING(512), allowNull: false },
      risk: { type: DataTypes.ENUM('read', 'write', 'destructive'), allowNull: false },
      args_sha256: { type: binary32, allowNull: false },
      arguments: { type: DataTypes.JSON, allowNull: false },
      challenge: { type: DataTypes.TEXT, allowNull: false },
      policy_id: { type: DataTypes.INTEGER.UNSIGNED, allowNull: false },
      required_approvals: { type: DataTypes.TINYINT.UNSIGNED, allowNull: false },
      approver_group: { type: DataTypes.STRING(64), allowNull: true },
      correlation_id: { type: DataTypes.CHAR(36), allowNull: false },
      created_at: { type: DataTypes.DATE(3), allowNull: false },
      expires_at: { type: DataTypes.DATE(3), allowNull: false },
      decided_at: { type: DataTypes.DATE(3), allowNull: true },
      consumed_at: { type: DataTypes.DATE(3), allowNull: true },
    });
    await queryInterface.addIndex('fw_approvals', ['status', 'expires_at'], { name: 'ix_status_exp' });
    await queryInterface.addIndex(
      'fw_approvals',
      ['agent_id', 'server_id', 'tool', 'args_sha256', 'status'],
      { name: 'ix_match' },
    );

    await queryInterface.createTable('fw_approval_signatures', {
      approval_id: { type: DataTypes.CHAR(36), allowNull: false, primaryKey: true },
      approver_id: { type: DataTypes.STRING(64), allowNull: false, primaryKey: true },
      decision: { type: DataTypes.ENUM('approve', 'deny'), allowNull: false },
      signature: { type: DataTypes.TEXT, allowNull: false },
      signed_at: { type: DataTypes.DATE(3), allowNull: false },
    });
    await queryInterface.addConstraint('fw_approval_signatures', {
      fields: ['approval_id'],
      type: 'foreign key',
      name: 'fk_sig_approval',
      references: { table: 'fw_approvals', field: 'id' },
    });
    await queryInterface.addConstraint('fw_approval_signatures', {
      fields: ['approver_id'],
      type: 'foreign key',
      name: 'fk_sig_approver',
      references: { table: 'fw_approvers', field: 'id' },
    });

    await queryInterface.createTable('fw_audit_log', {
      seq: { type: DataTypes.BIGINT.UNSIGNED, allowNull: false, primaryKey: true },
      occurred_at: { type: DataTypes.DATE(3), allowNull: false },
      event_type: { type: DataTypes.STRING(48), allowNull: false },
      correlation_id: { type: DataTypes.CHAR(36), allowNull: true },
      agent_id: { type: DataTypes.STRING(64), allowNull: true },
      server_id: { type: DataTypes.STRING(128), allowNull: true },
      tool: { type: DataTypes.STRING(128), allowNull: true },
      resource: { type: DataTypes.STRING(512), allowNull: true },
      rpc_id: { type: DataTypes.STRING(128), allowNull: true },
      args_hmac: { type: binary32, allowNull: true },
      decision: { type: DataTypes.STRING(32), allowNull: true },
      reason_code: { type: DataTypes.STRING(64), allowNull: true },
      metadata: { type: DataTypes.JSON, allowNull: false },
      prev_hash: { type: binary32, allowNull: false },
      entry_hash: { type: binary32, allowNull: false },
    });
    await queryInterface.addIndex('fw_audit_log', ['correlation_id'], { name: 'ix_corr' });
    await queryInterface.addIndex('fw_audit_log', ['agent_id', 'occurred_at'], { name: 'ix_agent_time' });
    await queryInterface.addIndex('fw_audit_log', ['tool', 'occurred_at'], { name: 'ix_tool_time' });
    await queryInterface.addIndex('fw_audit_log', ['decision', 'occurred_at'], { name: 'ix_decision_time' });

    await queryInterface.createTable('fw_audit_head', {
      id: { type: DataTypes.TINYINT.UNSIGNED, allowNull: false, primaryKey: true },
      last_seq: { type: DataTypes.BIGINT.UNSIGNED, allowNull: false },
      last_hash: { type: binary32, allowNull: false },
    });
    await queryInterface.sequelize.query(
      'ALTER TABLE `fw_audit_head` ADD CONSTRAINT `ck_singleton` CHECK (`id` = 1)',
    );
    await queryInterface.sequelize.query(
      "INSERT IGNORE INTO `fw_audit_head` (`id`, `last_seq`, `last_hash`) VALUES (1, 0, UNHEX(REPEAT('00', 32)))",
    );

    await createAuditTriggers(queryInterface.sequelize);
  },

  async down() {
    throw new Error('Firewall schema rollback is disabled to prevent accidental loss of data and audit history');
  },
};
