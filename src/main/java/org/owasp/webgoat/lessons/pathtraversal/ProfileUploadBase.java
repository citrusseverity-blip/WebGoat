package org.owasp.webgoat.lessons.pathtraversal;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.io.FilenameUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.WebSession;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.FileSystemUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

@AllArgsConstructor
@Getter
public class ProfileUploadBase extends AssignmentEndpoint {

  private String webGoatHomeDirectory;
  private WebSession webSession;

  protected AttackResult execute(MultipartFile file, String fullName) {
    if (file.isEmpty()) {
      return failed(this).feedback("path-traversal-profile-empty-file").build();
    }
    if (StringUtils.isEmpty(fullName)) {
      return failed(this).feedback("path-traversal-profile-empty-name").build();
    }

    File uploadDirectory = cleanupAndCreateDirectoryForUser();

    try {
      // Check if path traversal was attempted (for lesson detection)
      var intendedFile = new File(uploadDirectory, fullName);
      boolean traversalAttempted = attemptWasMade(uploadDirectory, intendedFile);
      
      if (traversalAttempted) {
        // Path traversal detected - mark lesson as solved but prevent the actual write
        return solvedIt(intendedFile);
      }
      
      // Validate and sanitize the filename to prevent path traversal
      String sanitizedFilename = sanitizeFilename(fullName);
      if (sanitizedFilename == null || sanitizedFilename.isEmpty()) {
        return failed(this)
            .feedback("path-traversal-profile-invalid-filename")
            .build();
      }
      
      // Create the file with the sanitized filename
      var uploadedFile = new File(uploadDirectory, sanitizedFilename);
      
      // Final validation: ensure the canonical path is within the upload directory
      if (!isWithinDirectory(uploadDirectory, uploadedFile)) {
        return failed(this)
            .feedback("path-traversal-profile-invalid-path")
            .build();
      }
      
      // Safe to create and write the file
      uploadedFile.createNewFile();
      FileCopyUtils.copy(file.getBytes(), uploadedFile);

      return informationMessage(this)
          .feedback("path-traversal-profile-updated")
          .feedbackArgs(uploadedFile.getAbsoluteFile())
          .build();

    } catch (IOException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }
  
  /**
   * Sanitizes a filename by removing path components and keeping only the base filename.
   * This prevents path traversal attacks by stripping directory separators and parent references.
   * 
   * @param filename the filename to sanitize
   * @return the sanitized filename containing only the base name, or null if invalid
   */
  private String sanitizeFilename(String filename) {
    if (filename == null || filename.isEmpty()) {
      return null;
    }
    
    // Use FilenameUtils to extract just the base name, removing any path components
    String baseName = FilenameUtils.getName(filename);
    
    // Additional validation: reject if the result is empty or contains suspicious patterns
    if (baseName == null || baseName.isEmpty() || baseName.equals(".") || baseName.equals("..")) {
      return null;
    }
    
    return baseName;
  }
  
  /**
   * Validates that a file is within the specified directory by comparing canonical paths.
   * This prevents path traversal attacks by ensuring the resolved path stays within bounds.
   * 
   * @param directory the directory that should contain the file
   * @param file the file to validate
   * @return true if the file is within the directory, false otherwise
   * @throws IOException if an I/O error occurs while resolving canonical paths
   */
  private boolean isWithinDirectory(File directory, File file) throws IOException {
    String canonicalDirectory = directory.getCanonicalPath();
    String canonicalFile = file.getCanonicalPath();
    
    // Ensure the file's canonical path starts with the directory's canonical path
    // and is not equal to it (file must be inside, not the directory itself)
    return canonicalFile.startsWith(canonicalDirectory + File.separator);
  }

  @SneakyThrows
  protected File cleanupAndCreateDirectoryForUser() {
    var uploadDirectory =
        new File(this.webGoatHomeDirectory, "/PathTraversal/" + webSession.getUserName());
    if (uploadDirectory.exists()) {
      FileSystemUtils.deleteRecursively(uploadDirectory);
    }
    Files.createDirectories(uploadDirectory.toPath());
    return uploadDirectory;
  }

  private boolean attemptWasMade(File expectedUploadDirectory, File uploadedFile)
      throws IOException {
    return !expectedUploadDirectory
        .getCanonicalPath()
        .equals(uploadedFile.getParentFile().getCanonicalPath());
  }

  private AttackResult solvedIt(File uploadedFile) throws IOException {
    if (uploadedFile.getCanonicalFile().getParentFile().getName().endsWith("PathTraversal")) {
      return success(this).build();
    }
    return failed(this)
        .attemptWasMade()
        .feedback("path-traversal-profile-attempt")
        .feedbackArgs(uploadedFile.getCanonicalPath())
        .build();
  }

  public ResponseEntity<?> getProfilePicture() {
    return ResponseEntity.ok()
        .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
        .body(getProfilePictureAsBase64());
  }

  protected byte[] getProfilePictureAsBase64() {
    var profilePictureDirectory =
        new File(this.webGoatHomeDirectory, "/PathTraversal/" + webSession.getUserName());
    var profileDirectoryFiles = profilePictureDirectory.listFiles();

    if (profileDirectoryFiles != null && profileDirectoryFiles.length > 0) {
      return Arrays.stream(profileDirectoryFiles)
          .filter(file -> FilenameUtils.isExtension(file.getName(), List.of("jpg", "png")))
          .findFirst()
          .map(
              file -> {
                try (var inputStream = new FileInputStream(profileDirectoryFiles[0])) {
                  return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
                } catch (IOException e) {
                  return defaultImage();
                }
              })
          .orElse(defaultImage());
    } else {
      return defaultImage();
    }
  }

  @SneakyThrows
  protected byte[] defaultImage() {
    var inputStream = getClass().getResourceAsStream("/images/account.png");
    return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
  }
}
