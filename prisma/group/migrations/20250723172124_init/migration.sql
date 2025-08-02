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

-- CreateIndex
CREATE UNIQUE INDEX "group_name_key" ON "group"("name");

-- CreateIndex
CREATE UNIQUE INDEX "group_member_id" ON "group_membership"("group_id", "member_id", "membership_type");

-- AddForeignKey
ALTER TABLE "group_membership" ADD CONSTRAINT "group_id" FOREIGN KEY ("group_id") REFERENCES "group"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
