/*
  Warnings:

  - You are about to drop the `client_user` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `permission_policy` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "client_user" DROP CONSTRAINT "client_id";

-- DropTable
DROP TABLE "client_user";

-- DropTable
DROP TABLE "permission_policy";
