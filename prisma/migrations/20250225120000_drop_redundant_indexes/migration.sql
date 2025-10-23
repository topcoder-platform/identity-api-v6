-- Drop redundant single-column indexes now covered by composite indexes
DROP INDEX IF EXISTS "email_address_idx";
DROP INDEX IF EXISTS "user_status_idx";
