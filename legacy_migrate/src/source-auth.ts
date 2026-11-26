import mysql, { type RowDataPacket } from 'mysql2/promise';
import type { Client, Role, RoleAssignment } from '../generated/source-auth';

const auditColumns = 'createdBy, createdAt, modifiedBy, modifiedAt';
const tables = {
  role: { name: 'role', columns: 'id, name' },
  client: { name: 'client', columns: 'id, client_id AS clientId, name, redirect_uri AS redirectUri, secret' },
  roleAssignment: { name: 'role_assignment', columns: 'id, role_id AS roleId, subject_id AS subjectId' },
} as const;

type AuthRows = { role: Role; client: Client; roleAssignment: RoleAssignment };
export type AuthTable = keyof AuthRows;
export function isAuthTable(name: string): name is AuthTable {
  return Object.prototype.hasOwnProperty.call(tables, name);
}

export function createAuthSource(url: string) {
  // The MariaDB connector accepts ssl=true. mysql2 requires TLS options.
  const uri = new URL(url);
  if (uri.searchParams.get('ssl') === 'true') uri.searchParams.set('ssl', '{}');
  const pool = mysql.createPool({ uri: uri.toString(), timezone: 'Z' });
  const changeFilter = ' WHERE createdAt >= ? OR modifiedAt >= ?';

  return {
    async read<T extends AuthTable>(table: T, since: Date | null, offset: number, limit: number) {
      const { name, columns } = tables[table];
      const sql = `SELECT ${columns}, ${auditColumns} FROM \`${name}\`${since ? changeFilter : ''} ORDER BY id LIMIT ? OFFSET ?`;
      const [rows] = await pool.query<(AuthRows[T] & RowDataPacket)[]>(sql, [
        ...(since ? [since, since] : []), limit, offset,
      ]);
      return rows;
    },
    async count(table: AuthTable, since: Date) {
      const [rows] = await pool.query<RowDataPacket[]>(
        `SELECT COUNT(*) AS total FROM \`${tables[table].name}\`${changeFilter}`,
        [since, since],
      );
      return Number(rows[0].total);
    },
    ping: () => pool.query('SELECT 1'),
    close: () => pool.end(),
  };
}
