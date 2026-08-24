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

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/**
 * Tests for SqlStatementValidator to ensure it properly restricts SQL operations
 * and prevents abuse of lesson endpoints.
 */
public class SqlStatementValidatorTest {

  @Test
  public void testValidateSelectOnly_AllowsValidSelect() {
    assertDoesNotThrow(() -> 
        SqlStatementValidator.validateSelectOnly("SELECT * FROM employees WHERE userid=96134"));
    assertDoesNotThrow(() -> 
        SqlStatementValidator.validateSelectOnly("SELECT department FROM employees WHERE userid=96134;"));
  }

  @Test
  public void testValidateSelectOnly_BlocksUpdate() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateSelectOnly("UPDATE employees SET department='Sales'"));
    assertTrue(exception.getMessage().contains("Only SELECT queries are allowed"));
  }

  @Test
  public void testValidateSelectOnly_BlocksInsert() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateSelectOnly("INSERT INTO employees VALUES (1, 'test')"));
    assertTrue(exception.getMessage().contains("Only SELECT queries are allowed"));
  }

  @Test
  public void testValidateSelectOnly_BlocksDelete() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateSelectOnly("DELETE FROM employees"));
    assertTrue(exception.getMessage().contains("Only SELECT queries are allowed"));
  }

  @Test
  public void testValidateSelectOnly_BlocksDDL() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateSelectOnly("DROP TABLE employees"));
    assertTrue(exception.getMessage().contains("DDL operations are not allowed"));
  }

  @Test
  public void testValidateSelectOnly_BlocksGrant() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateSelectOnly("GRANT SELECT ON employees TO user"));
    assertTrue(exception.getMessage().contains("DCL operations are not allowed"));
  }

  @Test
  public void testValidateSelectOnly_BlocksSchemaQualifier() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateSelectOnly("SELECT * FROM other_schema.employees"));
    assertTrue(exception.getMessage().contains("Schema-qualified table references are not allowed"));
  }

  @Test
  public void testValidateUpdateOnly_AllowsValidUpdate() {
    assertDoesNotThrow(() -> 
        SqlStatementValidator.validateUpdateOnly("UPDATE employees SET department='Sales' WHERE last_name='Barnett'"));
  }

  @Test
  public void testValidateUpdateOnly_BlocksSelect() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateUpdateOnly("SELECT * FROM employees"));
    assertTrue(exception.getMessage().contains("Only UPDATE queries are allowed"));
  }

  @Test
  public void testValidateUpdateOnly_BlocksDDL() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateUpdateOnly("ALTER TABLE employees ADD COLUMN phone VARCHAR(20)"));
    assertTrue(exception.getMessage().contains("DDL operations are not allowed"));
  }

  @Test
  public void testValidateUpdateOnly_BlocksSchemaQualifier() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateUpdateOnly("UPDATE other_schema.employees SET department='Sales'"));
    assertTrue(exception.getMessage().contains("Schema-qualified table references are not allowed"));
  }

  @Test
  public void testValidateAlterTableOnly_AllowsValidAlterTable() {
    assertDoesNotThrow(() -> 
        SqlStatementValidator.validateAlterTableOnly("ALTER TABLE employees ADD COLUMN phone VARCHAR(20)"));
  }

  @Test
  public void testValidateAlterTableOnly_BlocksSelect() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateAlterTableOnly("SELECT * FROM employees"));
    assertTrue(exception.getMessage().contains("Only ALTER TABLE operations are allowed"));
  }

  @Test
  public void testValidateAlterTableOnly_BlocksUpdate() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateAlterTableOnly("UPDATE employees SET department='Sales'"));
    assertTrue(exception.getMessage().contains("Only ALTER TABLE operations are allowed"));
  }

  @Test
  public void testValidateAlterTableOnly_BlocksDrop() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateAlterTableOnly("DROP TABLE employees"));
    assertTrue(exception.getMessage().contains("Only ALTER TABLE operations are allowed"));
  }

  @Test
  public void testValidateAlterTableOnly_BlocksGrant() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateAlterTableOnly("GRANT SELECT ON employees TO user"));
    assertTrue(exception.getMessage().contains("DCL operations are not allowed"));
  }

  @Test
  public void testValidateAlterTableOnly_BlocksSchemaQualifier() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateAlterTableOnly("ALTER TABLE other_schema.employees ADD COLUMN phone VARCHAR(20)"));
    assertTrue(exception.getMessage().contains("Schema-qualified table references are not allowed"));
  }

  @Test
  public void testValidateGrantOnly_AllowsValidGrant() {
    assertDoesNotThrow(() -> 
        SqlStatementValidator.validateGrantOnly("GRANT SELECT ON grant_rights TO unauthorized_user"));
  }

  @Test
  public void testValidateGrantOnly_BlocksSelect() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateGrantOnly("SELECT * FROM grant_rights"));
    assertTrue(exception.getMessage().contains("Only GRANT operations are allowed"));
  }

  @Test
  public void testValidateGrantOnly_BlocksUpdate() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateGrantOnly("UPDATE grant_rights SET value='test'"));
    assertTrue(exception.getMessage().contains("Only GRANT operations are allowed"));
  }

  @Test
  public void testValidateGrantOnly_BlocksRevoke() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateGrantOnly("REVOKE SELECT ON grant_rights FROM unauthorized_user"));
    assertTrue(exception.getMessage().contains("Only GRANT operations are allowed"));
  }

  @Test
  public void testValidateGrantOnly_BlocksDDL() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateGrantOnly("DROP TABLE grant_rights"));
    assertTrue(exception.getMessage().contains("DDL operations are not allowed"));
  }

  @Test
  public void testValidateGrantOnly_BlocksSchemaQualifier() {
    SecurityException exception = assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateGrantOnly("GRANT SELECT ON other_schema.grant_rights TO unauthorized_user"));
    assertTrue(exception.getMessage().contains("Schema-qualified table references are not allowed"));
  }

  @Test
  public void testNullQuery() {
    assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateSelectOnly(null));
  }

  @Test
  public void testEmptyQuery() {
    assertThrows(SecurityException.class, () ->
        SqlStatementValidator.validateSelectOnly(""));
  }

  @Test
  public void testCommentsAreRemoved() {
    // Comments should be stripped before validation
    assertDoesNotThrow(() -> 
        SqlStatementValidator.validateSelectOnly("SELECT * FROM employees -- WHERE userid=1"));
  }

  @Test
  public void testMultilineCommentsAreRemoved() {
    assertDoesNotThrow(() -> 
        SqlStatementValidator.validateSelectOnly("SELECT * FROM employees /* comment */ WHERE userid=1"));
  }
}
