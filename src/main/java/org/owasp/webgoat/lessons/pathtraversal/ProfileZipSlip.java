package org.owasp.webgoat.lessons.pathtraversal;

import static org.springframework.http.MediaType.ALL_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.WebSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@AssignmentHints({
  "path-traversal-zip-slip.hint1",
  "path-traversal-zip-slip.hint2",
  "path-traversal-zip-slip.hint3",
  "path-traversal-zip-slip.hint4"
})
@Slf4j
public class ProfileZipSlip extends ProfileUploadBase {

  public ProfileZipSlip(
      @Value("${webgoat.server.directory}") String webGoatHomeDirectory, WebSession webSession) {
    super(webGoatHomeDirectory, webSession);
  }

  @PostMapping(
      value = "/PathTraversal/zip-slip",
      consumes = ALL_VALUE,
      produces = APPLICATION_JSON_VALUE)
  @ResponseBody
  public AttackResult uploadFileHandler(@RequestParam("uploadedFileZipSlip") MultipartFile file) {
    if (!file.getOriginalFilename().toLowerCase().endsWith(".zip")) {
      return failed(this).feedback("path-traversal-zip-slip.no-zip").build();
    } else {
      return processZipUpload(file);
    }
  }

  @SneakyThrows
  private AttackResult processZipUpload(MultipartFile file) {
    var tmpZipDirectory = Files.createTempDirectory(getWebSession().getUserName());
    cleanupAndCreateDirectoryForUser();
    var currentImage = getProfilePictureAsBase64();

    try {
      // Validate and sanitize the uploaded filename to prevent path traversal
      String sanitizedFilename = sanitizeFilename(file.getOriginalFilename());
      var uploadedZipFile = tmpZipDirectory.resolve(sanitizedFilename);
      
      // Ensure the resolved path is within the temporary directory
      if (!isWithinDirectory(tmpZipDirectory.toFile(), uploadedZipFile.toFile())) {
        return failed(this).output("Invalid file path").build();
      }
      
      FileCopyUtils.copy(file.getBytes(), uploadedZipFile.toFile());

      ZipFile zip = new ZipFile(uploadedZipFile.toFile());
      Enumeration<? extends ZipEntry> entries = zip.entries();
      while (entries.hasMoreElements()) {
        ZipEntry e = entries.nextElement();
        
        // Validate ZIP entry name to prevent path traversal (Zip Slip vulnerability)
        File f = new File(tmpZipDirectory.toFile(), e.getName());
        
        // Check if the canonical path of the extracted file is within the temporary directory
        if (!isWithinDirectory(tmpZipDirectory.toFile(), f)) {
          log.warn("Zip Slip attempt detected: entry '{}' would extract outside temporary directory", e.getName());
          continue; // Skip this entry
        }
        
        // Create parent directories if needed
        File parentDir = f.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
          parentDir.mkdirs();
        }
        
        InputStream is = zip.getInputStream(e);
        Files.copy(is, f.toPath(), StandardCopyOption.REPLACE_EXISTING);
      }

      return isSolved(currentImage, getProfilePictureAsBase64());
    } catch (IOException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  /**
   * Validates that a file is within a specified directory to prevent path traversal attacks.
   * 
   * @param directory the parent directory
   * @param file the file to validate
   * @return true if the file is within the directory, false otherwise
   * @throws IOException if an I/O error occurs
   */
  private boolean isWithinDirectory(File directory, File file) throws IOException {
    String canonicalDirectory = directory.getCanonicalPath();
    String canonicalFile = file.getCanonicalPath();
    return canonicalFile.startsWith(canonicalDirectory + File.separator) 
        || canonicalFile.equals(canonicalDirectory);
  }

  /**
   * Sanitizes a filename by removing path components and keeping only the base name.
   * 
   * @param filename the filename to sanitize
   * @return the sanitized filename
   */
  private String sanitizeFilename(String filename) {
    if (filename == null) {
      return "upload.zip";
    }
    // Remove any path components and keep only the filename
    File f = new File(filename);
    String name = f.getName();
    // Additional safety: remove any remaining path separators
    name = name.replaceAll("[/\\\\]", "_");
    return name.isEmpty() ? "upload.zip" : name;
  }

  private AttackResult isSolved(byte[] currentImage, byte[] newImage) {
    if (Arrays.equals(currentImage, newImage)) {
      return failed(this).output("path-traversal-zip-slip.extracted").build();
    }
    return success(this).output("path-traversal-zip-slip.extracted").build();
  }

  @GetMapping("/PathTraversal/zip-slip/")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture() {
    return super.getProfilePicture();
  }

  @GetMapping("/PathTraversal/zip-slip/profile-image/{username}")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(@PathVariable("username") String username) {
    return ResponseEntity.notFound().build();
  }
}
