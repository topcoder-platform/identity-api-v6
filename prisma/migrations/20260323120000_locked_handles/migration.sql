-- CreateTable
CREATE TABLE "identity"."locked_handles" (
    "locked_handle_id" SERIAL NOT NULL,
    "locked_handle" VARCHAR(50) NOT NULL,
    "locked_handle_lower" VARCHAR(50) NOT NULL,
    "create_date" TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "pk_locked_handles" PRIMARY KEY ("locked_handle_id")
);

-- CreateIndex
CREATE UNIQUE INDEX "locked_handles_locked_handle_lower_key" ON "identity"."locked_handles"("locked_handle_lower");

-- CreateFunction
CREATE OR REPLACE FUNCTION "identity"."lock_deleted_handle"()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.handle IS NULL
        OR OLD.handle LIKE 'DELETED_USER_%'
        OR NEW.handle IS NULL
        OR NEW.handle NOT LIKE 'DELETED_USER_%' THEN
        RETURN NEW;
    END IF;

    INSERT INTO "identity"."locked_handles" ("locked_handle", "locked_handle_lower")
    VALUES (OLD.handle, LOWER(OLD.handle))
    ON CONFLICT ("locked_handle_lower") DO NOTHING;

    RETURN NEW;
END;
$$;

-- CreateTrigger
DROP TRIGGER IF EXISTS "trg_lock_deleted_handle" ON "identity"."user";

CREATE TRIGGER "trg_lock_deleted_handle"
AFTER UPDATE OF "handle" ON "identity"."user"
FOR EACH ROW
WHEN (OLD."handle" IS DISTINCT FROM NEW."handle")
EXECUTE FUNCTION "identity"."lock_deleted_handle"();
