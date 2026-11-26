import 'dotenv/config';
import { relative, resolve } from 'node:path';
import { defineConfig } from 'prisma/config';

const datasourceUrls: Record<string, string | undefined> = {
  'prisma/source-auth.schema.prisma': process.env.SOURCE_AUTH_MYSQL_URL,
  'prisma/source-identity.schema.prisma': process.env.SOURCE_IDENTITY_PG_URL,
  'prisma/target.schema.prisma': process.env.IDENTITY_DB_URL,
};

const schemaFlag = process.argv.findIndex(arg => arg === '--schema' || arg.startsWith('--schema='));
const selected = schemaFlag < 0
  ? 'prisma/target.schema.prisma'
  : process.argv[schemaFlag].split('=')[1] || process.argv[schemaFlag + 1];
const schema = relative(process.cwd(), resolve(selected));
if (!Object.prototype.hasOwnProperty.call(datasourceUrls, schema)) throw new Error(`Unknown Prisma schema: ${schema}`);

export default defineConfig({
  schema,
  datasource: { url: datasourceUrls[schema] },
});
