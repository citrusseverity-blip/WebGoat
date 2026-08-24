# SQL Injection Lesson Security Fix

## Overview
This fix addresses a critical security vulnerability in the SQL injection lesson endpoints (attack2-attack5) where authenticated users could execute arbitrary SQL commands beyond the intended lesson scope.

## Vulnerability Description
The four lesson endpoints (`/SqlInjection/attack2` through `/attack5`) were accepting user-supplied SQL queries without proper validation, allowing:
- Cross-schema access via fully qualified table names (e.g., `other_schema.table`)
- DDL operations (CREATE, DROP, ALTER, TRUNCATE)
- DCL operations (GRANT, REVOKE)
- Transaction control operations (COMMIT, ROLLBACK)
- Arbitrary DML operations beyond the lesson's intended scope

While these endpoints are part of training lessons, they posed a genuine security risk because:
1. Any self-registered WebGoat user could access them
2. The datasource is shared across users
3. The `LessonConnectionInvocationHandler` only sets the default schema but doesn't prevent fully qualified references or privilege operations
4. Operations execute with the datasource principal's full privileges

## Solution
A new `SqlStatementValidator` class was created to enforce statement-type restrictions on each lesson endpoint:

### SqlStatementValidator
- **validateSelectOnly()**: Allows only SELECT statements (Lesson 2)
- **validateUpdateOnly()**: Allows only UPDATE statements (Lesson 3)
- **validateAlterTableOnly()**: Allows only ALTER TABLE statements (Lesson 4)
- **validateGrantOnly()**: Allows only GRANT statements (Lesson 5)

Each validator:
1. Blocks schema-qualified table references (e.g., `schema.table`)
2. Blocks DDL operations (CREATE, DROP, ALTER, TRUNCATE, RENAME) except where specifically allowed
3. Blocks DCL operations (GRANT, REVOKE) except where specifically allowed
4. Blocks TCL operations (COMMIT, ROLLBACK, SAVEPOINT)
5. Blocks DML operations except the specific type allowed for that lesson
6. Removes SQL comments before validation to prevent bypass attempts
7. Uses word-boundary matching to prevent false positives

### Changes to Lesson Files
Each of the four vulnerable lesson files was updated to call the appropriate validator before executing the user-supplied query:

- **SqlInjectionLesson2.java**: Added `validateSelectOnly()` check
- **SqlInjectionLesson3.java**: Added `validateUpdateOnly()` check
- **SqlInjectionLesson4.java**: Added `validateAlterTableOnly()` check
- **SqlInjectionLesson5.java**: Added `validateGrantOnly()` check

When validation fails, the endpoint returns a failed result with a descriptive error message instead of executing the query.

## Testing
A comprehensive test suite (`SqlStatementValidatorTest.java`) was created to verify:
- Legitimate lesson solutions still work
- Malicious queries are blocked
- Schema-qualified references are blocked
- DDL/DCL/TCL operations are blocked where not allowed
- Comment-based bypasses are prevented
- Null and empty queries are rejected

## Impact
- **Security**: Prevents arbitrary SQL execution while maintaining lesson functionality
- **Functionality**: Legitimate lesson solutions continue to work as expected
- **User Experience**: Users attempting to abuse the endpoints receive clear error messages

## Files Modified
1. `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlStatementValidator.java` (new)
2. `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson2.java`
3. `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson3.java`
4. `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson4.java`
5. `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5.java`
6. `src/test/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlStatementValidatorTest.java` (new)

## Verification
The fix can be verified by:
1. Running the existing lesson tests to ensure legitimate solutions still work
2. Running the new `SqlStatementValidatorTest` to verify security restrictions
3. Attempting to execute malicious queries like:
   - `DROP TABLE employees` on attack2
   - `GRANT ALL PRIVILEGES ON *.* TO user` on attack3
   - `UPDATE other_schema.table SET value='x'` on attack3
   - `CREATE TABLE malicious (id INT)` on attack4
