export type DeploymentMode = 'module' | 'standalone';
export type StandaloneAuthMode = 'none' | 'basic';

export interface Config {
  postgres: {
    host: string;
    port: number;
    database: string;
    user: string;
    password: string;
  };
  port: number;
  nodeEnv: string;
  logLevel: string;
  proxySecret: string;
  allowPrivateNetworkDiagnostics: boolean;
  deploymentMode: DeploymentMode;
  standaloneAuth: {
    mode: StandaloneAuthMode;
    username: string;
    passwordHash: string;
  };
}

function getEnv(key: string, fallback?: string): string {
  const value = process.env[key];
  if (value !== undefined) {
    return value;
  }
  if (fallback !== undefined) {
    return fallback;
  }
  throw new Error(`Missing required environment variable: ${key}`);
}

function getEnvInt(key: string, fallback: number): number {
  const value = process.env[key];
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    throw new Error(`Invalid integer environment variable: ${key}`);
  }
  return parsed;
}

function getDeploymentMode(): DeploymentMode {
  const value = (process.env.DEPLOYMENT_MODE ?? 'module').toLowerCase();
  return value === 'standalone' ? 'standalone' : 'module';
}

function getStandaloneAuthMode(): StandaloneAuthMode {
  const value = (process.env.ROBIN_TOOLS_AUTH_MODE ?? 'basic').toLowerCase();
  return value === 'none' ? 'none' : 'basic';
}

export const config: Config = {
  postgres: {
    host: process.env.DB_HOST ?? getEnv('POSTGRES_HOST', 'postgres-backend'),
    port: getEnvInt('DB_PORT', getEnvInt('POSTGRES_PORT', 5432)),
    database: process.env.DB_NAME ?? getEnv('POSTGRES_DB', 'robin'),
    user: process.env.DB_USER ?? getEnv('POSTGRES_USER', 'robin'),
    password: process.env.DB_PASSWORD ?? getEnv('POSTGRES_PASSWORD', 'robin'),
  },
  port: getEnvInt('PORT', 3003),
  nodeEnv: getEnv('NODE_ENV', 'production'),
  logLevel: getEnv('LOG_LEVEL', 'info'),
  proxySecret: getEnv('MODULE_PROXY_SECRET', 'dev-secret-change-in-production'),
  allowPrivateNetworkDiagnostics: ['1', 'true', 'yes'].includes(
    (process.env.ROBIN_TOOLS_ALLOW_PRIVATE_PROBES ?? '').toLowerCase()
  ),
  deploymentMode: getDeploymentMode(),
  standaloneAuth: {
    mode: getStandaloneAuthMode(),
    username: getEnv('ROBIN_TOOLS_AUTH_USERNAME', 'admin'),
    passwordHash: getEnv('ROBIN_TOOLS_AUTH_PASSWORD_HASH', ''),
  },
};
