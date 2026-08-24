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

package org.owasp.webgoat.lessons.vulnerablecomponents;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.AnyTypePermission;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.NullPermission;
import com.thoughtworks.xstream.security.PrimitiveTypePermission;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson extends AssignmentEndpoint {

  // Maximum payload size in bytes to prevent resource exhaustion (100KB)
  private static final int MAX_PAYLOAD_SIZE = 102400;
  
  // Maximum XML nesting depth to prevent stack overflow
  private static final int MAX_XML_DEPTH = 10;

  @PostMapping("/VulnerableComponents/attack1")
  public @ResponseBody AttackResult completed(@RequestParam String payload) {
    
    // Validate payload size to prevent resource exhaustion
    if (payload != null && payload.length() > MAX_PAYLOAD_SIZE) {
      return failed(this)
          .feedback("vulnerable-components.close")
          .output("Payload exceeds maximum allowed size")
          .build();
    }
    
    // Validate XML depth to prevent deeply nested structures
    if (payload != null && getXmlDepth(payload) > MAX_XML_DEPTH) {
      return failed(this)
          .feedback("vulnerable-components.close")
          .output("XML structure exceeds maximum allowed depth")
          .build();
    }
    
    // Configure XStream with strict security permissions
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    
    // Clear all default permissions and set up strict allowlist
    xstream.addPermission(NoTypePermission.NONE);
    xstream.addPermission(NullPermission.NULL);
    xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
    
    // Only allow specific safe types required for this lesson
    xstream.allowTypes(new Class[] {
        ContactImpl.class,
        Contact.class,
        String.class,
        Integer.class
    });
    
    // Explicitly deny dangerous types that could be used in gadget chains
    xstream.denyTypes(new String[] {
        "java.beans.EventHandler",
        "java.lang.ProcessBuilder",
        "java.lang.Runtime",
        "javax.script.**",
        "com.sun.org.apache.xalan.**"
    });
    
    // Deny dynamic proxies which are commonly used in deserialization attacks
    xstream.denyTypeHierarchy(java.lang.reflect.Proxy.class);
    xstream.denyTypesByRegExp(new String[] {".*\\.dynamic-proxy"});
    
    Contact contact = null;

    try {
      if (!StringUtils.isEmpty(payload)) {
        payload =
            payload
                .replace("+", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("> ", ">")
                .replace(" <", "<");
      }
      contact = (Contact) xstream.fromXML(payload);
    } catch (Exception ex) {
      return failed(this).feedback("vulnerable-components.close").output(ex.getMessage()).build();
    }

    try {
      if (null != contact) {
        contact.getFirstName(); // trigger the example like
        // https://x-stream.github.io/CVE-2013-7285.html
      }
      if (!(contact instanceof ContactImpl)) {
        return success(this).feedback("vulnerable-components.success").build();
      }
    } catch (Exception e) {
      return success(this).feedback("vulnerable-components.success").output(e.getMessage()).build();
    }
    return failed(this).feedback("vulnerable-components.fromXML").feedbackArgs(contact).build();
  }
  
  /**
   * Calculate the maximum nesting depth of XML elements to prevent deeply nested structures
   * that could cause stack overflow or excessive resource consumption.
   * 
   * @param xml The XML string to analyze
   * @return The maximum nesting depth
   */
  private int getXmlDepth(String xml) {
    int depth = 0;
    int maxDepth = 0;
    boolean inTag = false;
    boolean closingTag = false;
    
    for (int i = 0; i < xml.length(); i++) {
      char c = xml.charAt(i);
      
      if (c == '<') {
        inTag = true;
        if (i + 1 < xml.length() && xml.charAt(i + 1) == '/') {
          closingTag = true;
        } else if (i + 1 < xml.length() && xml.charAt(i + 1) != '?' && xml.charAt(i + 1) != '!') {
          closingTag = false;
        }
      } else if (c == '>') {
        if (inTag) {
          if (closingTag) {
            depth--;
          } else if (i > 0 && xml.charAt(i - 1) != '/') {
            // Not a self-closing tag
            depth++;
            if (depth > maxDepth) {
              maxDepth = depth;
            }
          }
        }
        inTag = false;
        closingTag = false;
      }
    }
    
    return maxDepth;
  }
}
