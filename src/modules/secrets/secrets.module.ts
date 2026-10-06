import { Module } from '@nestjs/common';
import { Logger } from '@nestjs/common';

const logger = new Logger('SecretsBootstrap');

/**
 * Resolves secrets from an external secrets manager into process.env
 * *before* ConfigModule (and everything downstream of it) reads
 * anything — so the rest of the app never has to know or care whether a
 * given value came from `.env` or from Vault/AWS.
 *
 * SECRETS_PROVIDER=env  (default) — no-op, current .env behavior.
 * SECRETS_PROVIDER=vault — reads a KV v2 secret from HashiCorp Vault.
 * SECRETS_PROVIDER=aws   — reads a JSON secret from AWS Secrets Manager.
 *
 * This runs synchronously at module-graph construction time (a static
 * async initializer invoked from bootstrap() in main.ts, awaited before
 * NestFactory.create is ever called) rather than as a normal injectable
 * provider, because config values have to exist in process.env before
 * ConfigModule.forRoot() parses it — a regular DI provider would run too
 * late.
 */
export async function loadExternalSecrets(): Promise<void> {
  const provider = (process.env.SECRETS_PROVIDER || 'env').toLowerCase();

  if (provider === 'env') {
    return; // nothing to do — plain .env / process.env, as before
  }

  if (provider === 'vault') {
    await loadFromVault();
    return;
  }

  if (provider === 'aws') {
    await loadFromAwsSecretsManager();
    return;
  }

  logger.warn(`Unknown SECRETS_PROVIDER "${provider}" — falling back to plain env vars`);
}

async function loadFromVault(): Promise<void> {
  const addr = process.env.VAULT_ADDR;
  const token = process.env.VAULT_TOKEN;
  const path = process.env.VAULT_SECRET_PATH;

  if (!addr || !token || !path) {
    logger.error(
      'SECRETS_PROVIDER=vault requires VAULT_ADDR, VAULT_TOKEN and VAULT_SECRET_PATH — falling back to plain env vars',
    );
    return;
  }

  try {
    // Lazy require: keeps `node-vault` from being loaded (and Vault
    // reachability from mattering) at all for the default env provider.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const vault = require('node-vault')({ apiVersion: 'v1', endpoint: addr, token });
    const result = await vault.read(path);
    // KV v2 nests the actual key/value pairs under data.data.
    const data: Record<string, string> = result?.data?.data ?? result?.data ?? {};
    mergeIntoEnv(data, 'Vault');
  } catch (err) {
    logger.error(`Failed to load secrets from Vault: ${(err as Error).message}`);
    logger.warn('Continuing with plain env vars only');
  }
}

async function loadFromAwsSecretsManager(): Promise<void> {
  const region = process.env.AWS_REGION || 'us-east-1';
  const secretId = process.env.AWS_SECRET_ID;

  if (!secretId) {
    logger.error('SECRETS_PROVIDER=aws requires AWS_SECRET_ID — falling back to plain env vars');
    return;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
    const client = new SecretsManagerClient({ region });
    const response = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
    const raw = response.SecretString;
    if (!raw) {
      logger.error('AWS Secrets Manager returned a binary secret; expected a JSON string');
      return;
    }
    const data: Record<string, string> = JSON.parse(raw);
    mergeIntoEnv(data, 'AWS Secrets Manager');
  } catch (err) {
    logger.error(`Failed to load secrets from AWS Secrets Manager: ${(err as Error).message}`);
    logger.warn('Continuing with plain env vars only');
  }
}

function mergeIntoEnv(data: Record<string, unknown>, sourceLabel: string): void {
  let count = 0;
  for (const [key, value] of Object.entries(data)) {
    if (value === undefined || value === null) continue;
    // Values already present in process.env (e.g. deployment-injected
    // PORT, NODE_ENV) take priority over the secrets store, so an
    // operator can always override a single value locally without
    // editing the vault/secret entry.
    if (process.env[key] === undefined) {
      process.env[key] = String(value);
      count++;
    }
  }
  logger.log(`Loaded ${count} secret(s) from ${sourceLabel}`);
}

/**
 * Trivial module wrapper so this can still sit in Nest's module import
 * graph for discoverability, even though the actual work happens in
 * bootstrap() before the graph is built (see main.ts).
 */
@Module({})
export class SecretsModule {}
