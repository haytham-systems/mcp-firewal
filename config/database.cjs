const databaseUrl = process.env.MCP_FW_DATABASE_URL;

if (!databaseUrl) {
  throw new Error('MCP_FW_DATABASE_URL is required');
}

const config = {
  use_env_variable: 'MCP_FW_DATABASE_URL',
  url: databaseUrl,
  dialect: 'mysql',
  timezone: '+00:00',
  logging: false,
  pool: {
    max: 16,
    min: 0,
    acquire: 30_000,
    idle: 10_000,
  },
};

module.exports = {
  development: config,
  test: config,
  production: config,
};
