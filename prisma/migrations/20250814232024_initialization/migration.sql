CREATE SEQUENCE IF NOT EXISTS sequence_email_seq
    INCREMENT 1
    START 70100000
    MINVALUE 1
    MAXVALUE 9223372036854775807
    CACHE 1;

CREATE SEQUENCE IF NOT EXISTS sequence_user_seq
    INCREMENT 1
    START 88770000
    MINVALUE 1
    MAXVALUE 9223372036854775807
    CACHE 1;

-- CreateTable
CREATE TABLE "achievement_type_lu" (
    "achievement_type_id" DECIMAL(5,0) NOT NULL,
    "achievement_type_desc" VARCHAR(64) NOT NULL,

    CONSTRAINT "achv_type_lu_pkey" PRIMARY KEY ("achievement_type_id")
);

-- CreateTable
CREATE TABLE "country" (
    "country_code" VARCHAR(3) NOT NULL,
    "country_name" VARCHAR(40) NOT NULL,
    "modify_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
    "participating" DECIMAL(1,0),
    "default_taxform_id" DECIMAL(10,0),
    "longitude" DECIMAL(10,7),
    "latitude" DECIMAL(10,7),
    "region" VARCHAR(64),
    "iso_name" VARCHAR(128),
    "iso_alpha2_code" VARCHAR(2),
    "iso_alpha3_code" VARCHAR(3),

    CONSTRAINT "country_pkey" PRIMARY KEY ("country_code")
);

-- CreateTable
CREATE TABLE "dice_connection" (
    "id" SERIAL NOT NULL,
    "user_id" DECIMAL(10,0) NOT NULL,
    "connection" VARCHAR(50),
    "accepted" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "short_url" VARCHAR(100),
    "con_created_at" TIMESTAMP(6),

    CONSTRAINT "dice_connection_pk" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "email" (
    "user_id" DECIMAL(10,0),
    "email_id" DECIMAL(10,0) NOT NULL DEFAULT nextval('sequence_email_seq'::regclass),
    "email_type_id" DECIMAL(5,0),
    "address" VARCHAR(100),
    "create_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
    "modify_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
    "primary_ind" DECIMAL(1,0),
    "status_id" DECIMAL(3,0),

    CONSTRAINT "u110_23" PRIMARY KEY ("email_id")
);

-- CreateTable
CREATE TABLE "email_status_lu" (
    "status_id" DECIMAL(3,0) NOT NULL,
    "status_desc" VARCHAR(100),
    "create_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
    "modify_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "email_status_lu_pk" PRIMARY KEY ("status_id")
);

-- CreateTable
CREATE TABLE "email_type_lu" (
    "email_type_id" DECIMAL(5,0) NOT NULL,
    "email_type_desc" VARCHAR(100),
    "create_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
    "modify_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "email_type_lu_pk" PRIMARY KEY ("email_type_id")
);

-- CreateTable
CREATE TABLE "id_sequences" (
    "name" VARCHAR(254) NOT NULL,
    "next_block_start" DECIMAL(12,0) NOT NULL,
    "block_size" DECIMAL(10,0) NOT NULL,
    "exhausted" DECIMAL(1,0) NOT NULL DEFAULT 0,

    CONSTRAINT "id_sequences_pkey" PRIMARY KEY ("name")
);

-- CreateTable
CREATE TABLE "invalid_handles" (
    "invalid_handle_id" INTEGER NOT NULL,
    "invalid_handle" VARCHAR(20) NOT NULL,

    CONSTRAINT "pk_invalid_hand556" PRIMARY KEY ("invalid_handle_id")
);

-- CreateTable
CREATE TABLE "security_groups" (
    "group_id" DECIMAL(12,0) NOT NULL,
    "description" VARCHAR(254) NOT NULL,
    "challenge_group_ind" SMALLINT NOT NULL DEFAULT 0,
    "create_user_id" DECIMAL(12,0),

    CONSTRAINT "pk_security_groups" PRIMARY KEY ("group_id")
);

-- CreateTable
CREATE TABLE "security_status_lu" (
    "security_status_id" DECIMAL(3,0) NOT NULL,
    "status_desc" VARCHAR(200),

    CONSTRAINT "securitystatuslu_pkey" PRIMARY KEY ("security_status_id")
);

-- CreateTable
CREATE TABLE "security_user" (
    "login_id" DECIMAL(12,0) NOT NULL,
    "user_id" VARCHAR(50) NOT NULL,
    "password" VARCHAR(300) NOT NULL,
    "create_user_id" DECIMAL(12,0),
    "modify_date" TIMESTAMP(6),

    CONSTRAINT "pk_security_user" PRIMARY KEY ("login_id")
);

-- CreateTable
CREATE TABLE "social_login_provider" (
    "social_login_provider_id" DECIMAL(10,0) NOT NULL,
    "name" VARCHAR(50),

    CONSTRAINT "social_provider_prkey" PRIMARY KEY ("social_login_provider_id")
);

-- CreateTable
CREATE TABLE "sso_login_provider" (
    "sso_login_provider_id" DECIMAL(10,0) NOT NULL,
    "name" VARCHAR(50),
    "type" VARCHAR(50) NOT NULL,
    "identify_email_enabled" BOOLEAN NOT NULL DEFAULT true,
    "identify_handle_enabled" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "sso_provider_prkey" PRIMARY KEY ("sso_login_provider_id")
);

-- CreateTable
CREATE TABLE "user" (
    "user_id" DECIMAL(10,0) NOT NULL DEFAULT nextval('sequence_user_seq'::regclass),
    "first_name" VARCHAR(64),
    "last_name" VARCHAR(64),
    "create_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
    "modify_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
    "handle" VARCHAR(50) NOT NULL,
    "last_login" TIMESTAMP(6),
    "status" VARCHAR(3) NOT NULL,
    "activation_code" VARCHAR(32),
    "middle_name" VARCHAR(64),
    "handle_lower" VARCHAR(50),
    "timezone_id" DECIMAL(5,0),
    "last_site_hit_date" TIMESTAMP(6),
    "name_in_another_language" VARCHAR(64),
    "password" VARCHAR(16),
    "open_id" VARCHAR(200),
    "reg_source" VARCHAR(20),
    "utm_source" VARCHAR(50),
    "utm_medium" VARCHAR(50),
    "utm_campaign" VARCHAR(50),

    CONSTRAINT "u175_45" PRIMARY KEY ("user_id")
);

-- CreateTable
CREATE TABLE "user_2fa" (
    "id" SERIAL NOT NULL,
    "user_id" DECIMAL(10,0) NOT NULL,
    "mfa_enabled" BOOLEAN NOT NULL DEFAULT false,
    "dice_enabled" BOOLEAN NOT NULL DEFAULT false,
    "created_by" DECIMAL(10,0) NOT NULL,
    "created_at" TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "modified_by" DECIMAL(10,0) NOT NULL,
    "modified_at" TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_2fa_pk" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_achievement" (
    "user_id" DECIMAL(10,0) NOT NULL,
    "achievement_date" DATE NOT NULL,
    "achievement_type_id" DECIMAL(5,0) NOT NULL,
    "description" VARCHAR(255),
    "create_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_achievement_pkey" PRIMARY KEY ("user_id","achievement_type_id")
);

-- CreateTable
CREATE TABLE "user_group_xref" (
    "user_group_id" DECIMAL(12,0) NOT NULL,
    "login_id" DECIMAL(12,0),
    "group_id" DECIMAL(12,0),
    "create_user_id" DECIMAL(12,0),
    "security_status_id" DECIMAL(3,0),
    "create_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "pk_user_group_xref" PRIMARY KEY ("user_group_id")
);

-- CreateTable
CREATE TABLE "user_otp_email" (
    "id" SERIAL NOT NULL,
    "user_id" DECIMAL(10,0) NOT NULL,
    "mode" SMALLINT NOT NULL,
    "otp" VARCHAR(6) NOT NULL,
    "expire_at" TIMESTAMP(6) NOT NULL,
    "resend" BOOLEAN NOT NULL DEFAULT false,
    "fail_count" SMALLINT NOT NULL DEFAULT 0,

    CONSTRAINT "user_otp_email_pk" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_social_login" (
    "social_user_id" VARCHAR(254),
    "user_id" DECIMAL(10,0) NOT NULL,
    "social_login_provider_id" DECIMAL(10,0) NOT NULL,
    "social_user_name" VARCHAR(100) NOT NULL,
    "social_email" VARCHAR(100),
    "social_email_verified" BOOLEAN,
    "create_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
    "modify_date" TIMESTAMP(6),

    CONSTRAINT "user_social_prkey" PRIMARY KEY ("user_id","social_login_provider_id")
);

-- CreateTable
CREATE TABLE "user_sso_login" (
    "user_id" DECIMAL(10,0) NOT NULL,
    "sso_user_id" VARCHAR(100) NOT NULL,
    "sso_user_name" VARCHAR(100),
    "provider_id" DECIMAL(10,0) NOT NULL,
    "email" VARCHAR(100),

    CONSTRAINT "user_sso_prkey" PRIMARY KEY ("user_id","provider_id")
);

-- CreateTable
CREATE TABLE "user_status" (
    "user_id" DECIMAL(10,0) NOT NULL,
    "user_status_type_id" DECIMAL(3,0) NOT NULL,
    "user_status_id" DECIMAL(5,0),

    CONSTRAINT "userstatus_pk" PRIMARY KEY ("user_id","user_status_type_id")
);

-- CreateTable
CREATE TABLE "user_status_lu" (
    "user_status_id" DECIMAL(5,0) NOT NULL,
    "description" VARCHAR(100),

    CONSTRAINT "u113_26" PRIMARY KEY ("user_status_id")
);

-- CreateTable
CREATE TABLE "user_status_type_lu" (
    "user_status_type_id" DECIMAL(3,0) NOT NULL,
    "description" VARCHAR(100),

    CONSTRAINT "userstatustypelu_pk" PRIMARY KEY ("user_status_type_id")
);

-- CreateTable
CREATE TABLE "user_email_xref" (
    "user_id" DECIMAL(10,0) NOT NULL,
    "email_id" DECIMAL(10,0) NOT NULL,
    "is_primary" BOOLEAN NOT NULL,
    "status_id" DECIMAL(3,0) NOT NULL,
    "create_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,
    "modify_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_email_xref_pkey" PRIMARY KEY ("user_id","email_id")
);

-- CreateTable
CREATE TABLE "client" (
    "id" SERIAL NOT NULL,
    "client_id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "redirect_uri" VARCHAR(8192),
    "secret" TEXT,
    "createdBy" INTEGER,
    "createdAt" TIMESTAMP(0),
    "modifiedBy" INTEGER,
    "modifiedAt" TIMESTAMP(0),

    CONSTRAINT "client_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "role" (
    "id" SERIAL NOT NULL,
    "name" VARCHAR(45) NOT NULL,
    "createdBy" INTEGER,
    "createdAt" TIMESTAMP(0),
    "modifiedBy" INTEGER,
    "modifiedAt" TIMESTAMP(0),

    CONSTRAINT "role_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "role_assignment" (
    "id" SERIAL NOT NULL,
    "role_id" INTEGER NOT NULL,
    "subject_id" INTEGER NOT NULL,
    "createdBy" INTEGER,
    "createdAt" TIMESTAMP(0),
    "modifiedBy" INTEGER,
    "modifiedAt" TIMESTAMP(0),
    "subject_type" INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT "role_assignment_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "dice_connection_user_id_key" ON "dice_connection"("user_id");

-- CreateIndex
CREATE INDEX "dice_connection_connection_idx" ON "dice_connection"("connection");

-- CreateIndex
CREATE INDEX "email_address_idx" ON "email"("address");

-- CreateIndex
CREATE INDEX "email_user_id_idx" ON "email"("user_id", "primary_ind");

-- CreateIndex
CREATE UNIQUE INDEX "security_user_i2" ON "security_user"("user_id");

-- CreateIndex
CREATE INDEX "user_activ_code_idx" ON "user"("activation_code");

-- CreateIndex
CREATE INDEX "user_handle_idx" ON "user"("handle");

-- CreateIndex
CREATE INDEX "user_lower_handle_idx" ON "user"("handle_lower");

-- CreateIndex
CREATE INDEX "user_open_id_idx" ON "user"("open_id");

-- CreateIndex
CREATE INDEX "user_status_idx" ON "user"("status");

-- CreateIndex
CREATE UNIQUE INDEX "user_2fa_user_id_key" ON "user_2fa"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "user_grp_xref_i2" ON "user_group_xref"("login_id", "group_id");

-- CreateIndex
CREATE UNIQUE INDEX "user_otp_email_user_id_mode_key" ON "user_otp_email"("user_id", "mode");

-- CreateIndex
CREATE INDEX "idx_user_social_login_sso_user_id_provider_id" ON "user_sso_login"("sso_user_id", "provider_id");

-- CreateIndex
CREATE INDEX "user_email_xref_email_idx" ON "user_email_xref"("email_id");

-- CreateIndex
CREATE UNIQUE INDEX "client_client_id_key" ON "client"("client_id");

-- CreateIndex
CREATE UNIQUE INDEX "role_name_key" ON "role"("name");

-- CreateIndex
CREATE INDEX "subject_id_idx" ON "role_assignment"("subject_id");

-- CreateIndex
CREATE INDEX "role_id_idx" ON "role_assignment"("role_id");

-- CreateIndex
CREATE UNIQUE INDEX "role_subject_id_subject_type" ON "role_assignment"("role_id", "subject_id", "subject_type");

-- AddForeignKey
ALTER TABLE "dice_connection" ADD CONSTRAINT "dice_connection_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("user_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "email" ADD CONSTRAINT "email_emailstatuslu_fk" FOREIGN KEY ("status_id") REFERENCES "email_status_lu"("status_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "email" ADD CONSTRAINT "email_emailtypelu_fk" FOREIGN KEY ("email_type_id") REFERENCES "email_type_lu"("email_type_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "email" ADD CONSTRAINT "email_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("user_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_2fa" ADD CONSTRAINT "user_2fa_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("user_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_achievement" ADD CONSTRAINT "achv_type_fk" FOREIGN KEY ("achievement_type_id") REFERENCES "achievement_type_lu"("achievement_type_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_achievement" ADD CONSTRAINT "achv_user_fk" FOREIGN KEY ("user_id") REFERENCES "user"("user_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_group_xref" ADD CONSTRAINT "fk_user_grp_xref1" FOREIGN KEY ("login_id") REFERENCES "security_user"("login_id") ON DELETE CASCADE ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_group_xref" ADD CONSTRAINT "fk_user_grp_xref2" FOREIGN KEY ("group_id") REFERENCES "security_groups"("group_id") ON DELETE CASCADE ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_group_xref" ADD CONSTRAINT "usergroupxref_status_fk" FOREIGN KEY ("security_status_id") REFERENCES "security_status_lu"("security_status_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_otp_email" ADD CONSTRAINT "user_otp_email_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("user_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_social_login" ADD CONSTRAINT "user_social_provider_fk" FOREIGN KEY ("social_login_provider_id") REFERENCES "social_login_provider"("social_login_provider_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_social_login" ADD CONSTRAINT "user_social_user_fk" FOREIGN KEY ("user_id") REFERENCES "user"("user_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_sso_login" ADD CONSTRAINT "user_sso_login_provider_fk" FOREIGN KEY ("provider_id") REFERENCES "sso_login_provider"("sso_login_provider_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_sso_login" ADD CONSTRAINT "user_sso_login_user_fk" FOREIGN KEY ("user_id") REFERENCES "user"("user_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_status" ADD CONSTRAINT "userstatus_user_fk" FOREIGN KEY ("user_id") REFERENCES "user"("user_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_status" ADD CONSTRAINT "userstatus_userstatuslu_fk" FOREIGN KEY ("user_status_id") REFERENCES "user_status_lu"("user_status_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_status" ADD CONSTRAINT "userstatus_userstatustype_fk" FOREIGN KEY ("user_status_type_id") REFERENCES "user_status_type_lu"("user_status_type_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_email_xref" ADD CONSTRAINT "user_email_xref_user_fk" FOREIGN KEY ("user_id") REFERENCES "user"("user_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_email_xref" ADD CONSTRAINT "user_email_xref_email_fk" FOREIGN KEY ("email_id") REFERENCES "email"("email_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_email_xref" ADD CONSTRAINT "user_email_xref_status_id_fkey" FOREIGN KEY ("status_id") REFERENCES "email_status_lu"("status_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "role_assignment" ADD CONSTRAINT "role_id" FOREIGN KEY ("role_id") REFERENCES "role"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
