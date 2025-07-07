
## Local Deployment

Please make sure you have created 2 databases following ReadMe in codebase.

You need to make sure db url are configured correctly like:
```bash
export COMMON_OLTP_DB_URL="postgresql://coder:topcoder@localhost:5431/commondb?schema=common_oltp"

export AUTHORIZATION_DB_URL="postgresql://coder:topcoder@localhost:5432/authdb"
```

Sometimes you need to start redis before starting application. You can use docker to start it:
```bash
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

After that, please run
```bash
pnpm install

# run lint
pnpm run lint

# run test and generate coverage report
pnpm run test:cov

# Start application before running Postman tests
pnpm start

# Run Postman tests
pnpm run test:postman:authorization
pnpm run test:postman:group
pnpm run test:postman:roles
pnpm run test:postman:users
```

## Unique role name

As we have discussed in https://discussions.topcoder.com/discussion/36813/unique-role-name

The codebase and database are already checking unique role name.

In Java codebase, when creating/updating role with existing name, it directly returns existing record instead of throwing an error.

That is why PM thought it was not checking unique role name.

Anyway, we don't have to do anything for this requirement.

## Clean up the schema

I've cleaned schemas to include only really necessary tables.

There are only a few tables in authorization db. It's easy to check.

For common_oltp db, I only keep some of them. 
- I removed some relations in `user` and `security_group` so I can delete as many tables as possible.
- I kept some "_lu" tables for better understanding.
- `user_achievement` is used in Java codebase. But it can't be used in prisma. I think we'd better keep it.

## Make sure all the Controllers have API docs

Now they are fully updated including controllers and dtos.

The original codebase does't enable swagger docs. I added this function.

After starting application, you can check `http://localhost:3000/api-docs` to see swagger docs.


## Replace all the hard coded status numbers

Now all constants are in `src/core/constants/constants.ts`.

## validateMembership should be handled properly.

In Java codebase, you can check GroupResource.validateMembership(). It calls groupMembership.getMembershipTypeId()

In this function, it reads request.membershipType, and compares it with enum MembershipType name and get its value.

In current TypeScript codebase, I updated the code to make it easier to read. You can check group.service.ts#validateMembership.

Anyway, it's converting 'user' or 'group' to 1 or 2 so we can put it into db.

## Postman Tests

I've updated postman tests to include new jwt token and they should work now.

For user services, there are too many configs and too many services required. I couldn't make it working.

## JWT

You can use `jwt.js` in my submission to generate jwt.

It's much easier to use.

