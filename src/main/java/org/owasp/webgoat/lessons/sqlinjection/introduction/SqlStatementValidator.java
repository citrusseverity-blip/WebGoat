/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.sqlinjection.introduction;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Validates SQL statements to prevent abuse of intentionally vulnerable lesson endpoints.
 * This validator restricts SQL injection lesson endpoints to their intended scope,
 * preventing arbitrary database operations while still allowing lesson completion.
 */
public class SqlStatementValidator {

  private static final Pattern SCHEMA_QUALIFIER_PATTERN = Pattern.compile("\\w+\\.\\w+");
  
  // DDL operations that modify database structure
  private static final List<String> DDL_KEYWORDS = Arrays.asList(
      "CREATE", "DROP", "ALTER", "TRUNCATE", "RENAME"
  );
  
  // DCL operations that modify privileges
  private static final List<String> DCL_KEYWORDS = Arrays.asList(
      "GRANT", "REVOKE"
  );
  
  // TCL operations
  private static final List<String> TCL_KEYWORDS = Arrays.asList(
      "COMMIT", "ROLLBACK", "SAVEPOINT"
  );

  /**
   * Validates a SQL query for SELECT operations only.
   * Blocks DDL, DCL, TCL, and DML operations other than SELECT.
   * 
   * @param query The SQL query to validate
   * @throws SecurityException if the query contains disallowed operations
   */
  public static void validateSelectOnly(String query) {
    if (query == null || query.trim().isEmpty()) {
      throw new SecurityException("Query cannot be null or empty");
    }
    
    String normalizedQuery = normalizeQuery(query);
    
    // Block schema-qualified references
    if (containsSchemaQualifier(query)) {
      throw new SecurityException("Schema-qualified table references are not allowed");
    }
    
    // Block DDL operations
    if (containsAnyKeyword(normalizedQuery, DDL_KEYWORDS)) {
      throw new SecurityException("DDL operations are not allowed");
    }
    
    // Block DCL operations
    if (containsAnyKeyword(normalizedQuery, DCL_KEYWORDS)) {
      throw new SecurityException("DCL operations are not allowed");
    }
    
    // Block TCL operations
    if (containsAnyKeyword(normalizedQuery, TCL_KEYWORDS)) {
      throw new SecurityException("Transaction control operations are not allowed");
    }
    
    // Block DML operations other than SELECT
    if (containsAnyKeyword(normalizedQuery, Arrays.asList("INSERT", "UPDATE", "DELETE"))) {
      throw new SecurityException("Only SELECT queries are allowed");
    }
    
    // Ensure query starts with SELECT
    if (!normalizedQuery.trim().startsWith("SELECT")) {
      throw new SecurityException("Query must be a SELECT statement");
    }
  }

  /**
   * Validates a SQL query for UPDATE operations only.
   * Blocks DDL, DCL, TCL, and DML operations other than UPDATE.
   * 
   * @param query The SQL query to validate
   * @throws SecurityException if the query contains disallowed operations
   */
  public static void validateUpdateOnly(String query) {
    if (query == null || query.trim().isEmpty()) {
      throw new SecurityException("Query cannot be null or empty");
    }
    
    String normalizedQuery = normalizeQuery(query);
    
    // Block schema-qualified references
    if (containsSchemaQualifier(query)) {
      throw new SecurityException("Schema-qualified table references are not allowed");
    }
    
    // Block DDL operations
    if (containsAnyKeyword(normalizedQuery, DDL_KEYWORDS)) {
      throw new SecurityException("DDL operations are not allowed");
    }
    
    // Block DCL operations
    if (containsAnyKeyword(normalizedQuery, DCL_KEYWORDS)) {
      throw new SecurityException("DCL operations are not allowed");
    }
    
    // Block TCL operations
    if (containsAnyKeyword(normalizedQuery, TCL_KEYWORDS)) {
      throw new SecurityException("Transaction control operations are not allowed");
    }
    
    // Block DML operations other than UPDATE
    if (containsAnyKeyword(normalizedQuery, Arrays.asList("INSERT", "DELETE", "SELECT"))) {
      throw new SecurityException("Only UPDATE queries are allowed");
    }
    
    // Ensure query starts with UPDATE
    if (!normalizedQuery.trim().startsWith("UPDATE")) {
      throw new SecurityException("Query must be an UPDATE statement");
    }
  }

  /**
   * Validates a SQL query for ALTER TABLE operations only.
   * Blocks other DDL, DCL, TCL, and DML operations.
   * 
   * @param query The SQL query to validate
   * @throws SecurityException if the query contains disallowed operations
   */
  public static void validateAlterTableOnly(String query) {
    if (query == null || query.trim().isEmpty()) {
      throw new SecurityException("Query cannot be null or empty");
    }
    
    String normalizedQuery = normalizeQuery(query);
    
    // Block schema-qualified references
    if (containsSchemaQualifier(query)) {
      throw new SecurityException("Schema-qualified table references are not allowed");
    }
    
    // Block DDL operations other than ALTER TABLE
    if (containsAnyKeyword(normalizedQuery, Arrays.asList("CREATE", "DROP", "TRUNCATE", "RENAME"))) {
      throw new SecurityException("Only ALTER TABLE operations are allowed");
    }
    
    // Block DCL operations
    if (containsAnyKeyword(normalizedQuery, DCL_KEYWORDS)) {
      throw new SecurityException("DCL operations are not allowed");
    }
    
    // Block TCL operations
    if (containsAnyKeyword(normalizedQuery, TCL_KEYWORDS)) {
      throw new SecurityException("Transaction control operations are not allowed");
    }
    
    // Block DML operations
    if (containsAnyKeyword(normalizedQuery, Arrays.asList("INSERT", "UPDATE", "DELETE", "SELECT"))) {
      throw new SecurityException("Only ALTER TABLE operations are allowed");
    }
    
    // Ensure query starts with ALTER TABLE
    if (!normalizedQuery.trim().startsWith("ALTER") || !normalizedQuery.contains("TABLE")) {
      throw new SecurityException("Query must be an ALTER TABLE statement");
    }
  }

  /**
   * Validates a SQL query for GRANT operations only.
   * Blocks DDL, other DCL, TCL, and DML operations.
   * 
   * @param query The SQL query to validate
   * @throws SecurityException if the query contains disallowed operations
   */
  public static void validateGrantOnly(String query) {
    if (query == null || query.trim().isEmpty()) {
      throw new SecurityException("Query cannot be null or empty");
    }
    
    String normalizedQuery = normalizeQuery(query);
    
    // Block schema-qualified references
    if (containsSchemaQualifier(query)) {
      throw new SecurityException("Schema-qualified table references are not allowed");
    }
    
    // Block DDL operations
    if (containsAnyKeyword(normalizedQuery, DDL_KEYWORDS)) {
      throw new SecurityException("DDL operations are not allowed");
    }
    
    // Block DCL operations other than GRANT
    if (containsAnyKeyword(normalizedQuery, Arrays.asList("REVOKE"))) {
      throw new SecurityException("Only GRANT operations are allowed");
    }
    
    // Block TCL operations
    if (containsAnyKeyword(normalizedQuery, TCL_KEYWORDS)) {
      throw new SecurityException("Transaction control operations are not allowed");
    }
    
    // Block DML operations
    if (containsAnyKeyword(normalizedQuery, Arrays.asList("INSERT", "UPDATE", "DELETE", "SELECT"))) {
      throw new SecurityException("Only GRANT operations are allowed");
    }
    
    // Ensure query starts with GRANT
    if (!normalizedQuery.trim().startsWith("GRANT")) {
      throw new SecurityException("Query must be a GRANT statement");
    }
  }

  /**
   * Normalizes a SQL query by removing comments and extra whitespace.
   */
  private static String normalizeQuery(String query) {
    // Remove single-line comments
    String normalized = query.replaceAll("--[^\n]*", " ");
    // Remove multi-line comments
    normalized = normalized.replaceAll("/\\*.*?\\*/", " ");
    // Normalize whitespace
    normalized = normalized.replaceAll("\\s+", " ");
    return normalized.toUpperCase(Locale.ROOT);
  }

  /**
   * Checks if the query contains schema-qualified table references (e.g., schema.table).
   */
  private static boolean containsSchemaQualifier(String query) {
    // Remove string literals to avoid false positives
    String withoutStrings = query.replaceAll("'[^']*'", "");
    return SCHEMA_QUALIFIER_PATTERN.matcher(withoutStrings).find();
  }

  /**
   * Checks if the normalized query contains any of the specified keywords.
   */
  private static boolean containsAnyKeyword(String normalizedQuery, List<String> keywords) {
    for (String keyword : keywords) {
      // Use word boundaries to match whole words only
      if (normalizedQuery.matches(".*\\b" + keyword + "\\b.*")) {
        return true;
      }
    }
    return false;
  }
}
