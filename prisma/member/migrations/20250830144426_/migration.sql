-- CreateEnum
CREATE TYPE "MemberStatus" AS ENUM ('UNVERIFIED', 'ACTIVE', 'INACTIVE_USER_REQUEST', 'INACTIVE_DUPLICATE_ACCOUNT', 'INACTIVE_IRREGULAR_ACCOUNT', 'UNKNOWN');

-- CreateTable
CREATE TABLE "member" (
    "userId" BIGINT NOT NULL,
    "handle" TEXT NOT NULL,
    "handleLower" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "verified" BOOLEAN,
    "skillScore" DOUBLE PRECISION,
    "memberRatingId" BIGINT,
    "firstName" TEXT,
    "lastName" TEXT,
    "description" TEXT,
    "otherLangName" TEXT,
    "status" "MemberStatus",
    "newEmail" TEXT,
    "emailVerifyToken" TEXT,
    "emailVerifyTokenDate" TIMESTAMP(3),
    "newEmailVerifyToken" TEXT,
    "newEmailVerifyTokenDate" TIMESTAMP(3),
    "country" TEXT,
    "homeCountryCode" TEXT,
    "competitionCountryCode" TEXT,
    "photoURL" TEXT,
    "tracks" TEXT[],
    "loginCount" INTEGER,
    "lastLoginDate" TIMESTAMP(3),
    "availableForGigs" BOOLEAN,
    "skillScoreDeduction" DOUBLE PRECISION,
    "namesAndHandleAppearance" TEXT,
    "aggregatedSkills" JSONB,
    "enteredSkills" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3),
    "updatedBy" TEXT,

    CONSTRAINT "member_pkey" PRIMARY KEY ("userId")
);

-- CreateIndex
CREATE UNIQUE INDEX "member_handleLower_key" ON "member"("handleLower");

-- CreateIndex
CREATE UNIQUE INDEX "member_email_key" ON "member"("email");

-- CreateIndex
CREATE INDEX "member_handleLower_idx" ON "member"("handleLower");

-- CreateIndex
CREATE INDEX "member_email_idx" ON "member"("email");
