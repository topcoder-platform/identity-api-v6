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
CREATE TABLE "group" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "description" VARCHAR(2048),
    "createdBy" INTEGER,
    "createdAt" TIMESTAMP(0),
    "modifiedBy" INTEGER,
    "modifiedAt" TIMESTAMP(0),
    "private_group" BOOLEAN NOT NULL DEFAULT true,
    "self_register" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "group_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "permission_policy" (
    "id" VARCHAR(100) NOT NULL,
    "subjectId" VARCHAR(100) NOT NULL,
    "subjectType" VARCHAR(40) NOT NULL,
    "resource" VARCHAR(40) NOT NULL,
    "createdBy" INTEGER,
    "createdAt" TIMESTAMP(0),
    "modifiedBy" INTEGER,
    "modifiedAt" TIMESTAMP(0),
    "policy" TEXT NOT NULL,

    CONSTRAINT "permission_policy_pkey" PRIMARY KEY ("id")
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
CREATE TABLE "client_user" (
    "id" SERIAL NOT NULL,
    "client_id" INTEGER NOT NULL,
    "user_id" INTEGER NOT NULL,
    "scope" VARCHAR(8192),
    "createdBy" INTEGER,
    "createdAt" TIMESTAMP(0),
    "modifiedBy" INTEGER,
    "modifiedAt" TIMESTAMP(0),

    CONSTRAINT "client_user_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "group_membership" (
    "id" SERIAL NOT NULL,
    "group_id" INTEGER NOT NULL,
    "member_id" INTEGER NOT NULL,
    "membership_type" INTEGER NOT NULL DEFAULT 1,
    "createdBy" INTEGER,
    "createdAt" TIMESTAMP(0),
    "modifiedBy" INTEGER,
    "modifiedAt" TIMESTAMP(0),

    CONSTRAINT "group_membership_pkey" PRIMARY KEY ("id")
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
CREATE UNIQUE INDEX "client_client_id_key" ON "client"("client_id");

-- CreateIndex
CREATE UNIQUE INDEX "group_name_key" ON "group"("name");

-- CreateIndex
CREATE INDEX "subject_key" ON "permission_policy"("subjectId");

-- CreateIndex
CREATE UNIQUE INDEX "perm_policy_subject_resource_unique" ON "permission_policy"("subjectId", "subjectType", "resource");

-- CreateIndex
CREATE UNIQUE INDEX "role_name_key" ON "role"("name");

-- CreateIndex
CREATE INDEX "client_id_idx" ON "client_user"("client_id");

-- CreateIndex
CREATE INDEX "user_id_idx" ON "client_user"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "client_user_id" ON "client_user"("client_id", "user_id");

-- CreateIndex
CREATE UNIQUE INDEX "group_member_id" ON "group_membership"("group_id", "member_id", "membership_type");

-- CreateIndex
CREATE INDEX "subject_id_idx" ON "role_assignment"("subject_id");

-- CreateIndex
CREATE INDEX "role_id_idx" ON "role_assignment"("role_id");

-- CreateIndex
CREATE UNIQUE INDEX "role_subject_id_subject_type" ON "role_assignment"("role_id", "subject_id", "subject_type");

-- AddForeignKey
ALTER TABLE "client_user" ADD CONSTRAINT "client_id" FOREIGN KEY ("client_id") REFERENCES "client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "group_membership" ADD CONSTRAINT "group_id" FOREIGN KEY ("group_id") REFERENCES "group"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "role_assignment" ADD CONSTRAINT "role_id" FOREIGN KEY ("role_id") REFERENCES "role"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
