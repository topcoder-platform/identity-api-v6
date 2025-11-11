-- CreateIndex
CREATE INDEX "email_user_id_email_type_id_status_id_idx" ON "identity"."email"("user_id", "email_type_id", "status_id");

-- CreateIndex
CREATE INDEX "email_address_status_id_idx" ON "identity"."email"("address", "status_id");

-- CreateIndex
CREATE INDEX "role_assignment_subject_id_subject_type_idx" ON "identity"."role_assignment"("subject_id", "subject_type");

-- CreateIndex
CREATE INDEX "user_status_handle_lower_idx" ON "identity"."user"("status", "handle_lower");

-- CreateIndex
CREATE INDEX "user_email_xref_user_id_status_id_idx" ON "identity"."user_email_xref"("user_id", "status_id");

-- CreateIndex
CREATE INDEX "user_social_login_social_user_id_social_login_provider_id_idx" ON "identity"."user_social_login"("social_user_id", "social_login_provider_id");
