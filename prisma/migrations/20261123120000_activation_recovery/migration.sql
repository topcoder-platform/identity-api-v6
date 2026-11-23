ALTER TABLE "identity"."user_otp_email"
  ADD COLUMN "activation_sends" TIMESTAMP(3)[] NOT NULL DEFAULT '{}',
  ADD COLUMN "activation_failures" TIMESTAMP(3)[] NOT NULL DEFAULT '{}',
  ADD COLUMN "delivery_due_at" TIMESTAMP(3),
  ADD COLUMN "delivery_recipient" VARCHAR(100);

CREATE INDEX "activation_delivery_due_idx" ON "identity"."user_otp_email" ("delivery_due_at");
