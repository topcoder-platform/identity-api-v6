# Database Setup and Testing Guide

This guide provides instructions for setting up the PostgreSQL database roles and running Postman collection tests for the OLTP database project.

## Prerequisites

- PostgreSQL installed and running
- Node.js and pnpm package manager
- Newman (Postman CLI runner)
- Appropriate permissions to create database roles

## Database Role Setup

### Issue Description

When running the `common_oltp_db` script, you may encounter errors related to missing roles in your PostgreSQL database. These errors occur because the required role is not present in your database configuration.

### Solution

A `create-role.sh` script has been created to add the missing role and resolve these issues.

### Setup Instructions

1. **Make the script executable:**

   ```bash
   chmod +x create-role.sh
   ```

2. **Run the role creation script** (choose one option):

   **Option 1: Run with default authentication (peer-auth or local superuser)**

   ```bash
   ./create-role.sh
   ```

   **Option 2: Run with custom PostgreSQL credentials**

   ```bash
   PGUSER=your_pg_username PGPASSWORD=your_pg_password ./create-role.sh
   ```

3. **Run the main database script:**
   ```bash
   # After successful role creation, run:
   ./common_oltp_db
   ```

### Execution Timing

- Run the `create-role.sh` script **after** PostgreSQL is installed and running
- Ideally execute once at system setup or after resetting your database
- Must be completed **before** running the `common_oltp_db` script

## Postman Collection Testing

### Environment Configuration

Before running the Postman collection tests, you need to configure the environment variables:

1. **Update the environment file:**
   - Navigate to `/doc/postman_environment.json`
   - Add the `accessToken` value in the JSON file

### Running Tests

After configuring the environment, execute the Postman collection tests:

```bash
pnpm run test:postman:group
```

## Troubleshooting

### Database Role Issues

- Ensure PostgreSQL service is running before executing `create-role.sh`
- Verify you have sufficient privileges to create roles
- Check PostgreSQL logs if authentication fails

### Postman Test Issues

- Verify the `accessToken` is correctly set in the postman_environment.json file
- Ensure all required dependencies are installed with `pnpm install`
- Check that Newman is properly installed globally or as a dev dependency

## File Structure

```
project/
├── doc/
│   └── postman_environment.json   # Postman environment configuration
│    └── create-role.sh              # Role creation script
```

## Support

If you continue to experience issues:

1. Check PostgreSQL connection and permissions
2. Verify all prerequisites are installed
3. Review script output for specific error messages
4. Ensure environment variables are correctly configured
