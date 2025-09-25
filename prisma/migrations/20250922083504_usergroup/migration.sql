CREATE SEQUENCE IF NOT EXISTS sequence_user_group_seq
    INCREMENT 1
    START 88770000
    MINVALUE 1
    MAXVALUE 9223372036854775807
    CACHE 1;

-- AlterTable
ALTER TABLE "user_group_xref" ALTER COLUMN "user_group_id" SET DEFAULT nextval('sequence_user_group_seq'::regclass);
