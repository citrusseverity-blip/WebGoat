# Security Fix: Maven Wrapper JAR Verification

## Issue
The Maven Wrapper scripts (`mvnw`, `mvnw.cmd`) and the Java fallback downloader (`MavenWrapperDownloader.java`) downloaded and executed the wrapper JAR without verifying its integrity. This allowed potential arbitrary code execution if a malicious JAR was served from a compromised repository, mirror, proxy, or modified build environment.

## Root Cause
The downloader implementations in all three components:
1. Unix launcher (`mvnw`) - wget/curl download paths
2. Windows launcher (`mvnw.cmd`) - PowerShell download
3. Java fallback (`MavenWrapperDownloader.java`)

All downloaded the JAR from a configurable URL and immediately placed it on the Java classpath for execution without any cryptographic verification.

## Solution Implemented

### 1. Added Checksum Property
- Added `wrapperSha256Sum` property to `.mvn/wrapper/maven-wrapper.properties`
- This property stores the expected SHA-256 checksum of the legitimate wrapper JAR

### 2. Modified Unix Launcher (`mvnw`)
- Reads the `wrapperSha256Sum` property from maven-wrapper.properties
- After download (via wget, curl, or Java fallback), verifies the downloaded JAR's SHA-256 checksum
- Uses `shasum -a 256` or `sha256sum` (whichever is available)
- If verification fails:
  - Prints error message with expected vs actual checksums
  - Deletes the downloaded JAR
  - Exits with error code 1
- If no checksum is provided, prints a warning but continues (backward compatibility)

### 3. Modified Windows Launcher (`mvnw.cmd`)
- Reads the `wrapperSha256Sum` property from maven-wrapper.properties
- After PowerShell download, verifies the downloaded JAR's SHA-256 checksum
- Uses PowerShell's `Get-FileHash` cmdlet with SHA256 algorithm
- If verification fails:
  - Prints error message with expected vs actual checksums
  - Deletes the downloaded JAR
  - Exits with error code 1
- If no checksum is provided, prints a warning but continues (backward compatibility)

### 4. Modified Java Fallback Downloader (`MavenWrapperDownloader.java`)
- Added import for `java.security.MessageDigest`
- Added constant `PROPERTY_NAME_WRAPPER_SHA256SUM` for the checksum property name
- Reads the `wrapperSha256Sum` property from maven-wrapper.properties
- After download, calculates the SHA-256 checksum of the downloaded file
- Implements `calculateSHA256()` method using MessageDigest
- If verification fails:
  - Prints error message with expected vs actual checksums
  - Deletes the downloaded JAR
  - Exits with error code 1
- If no checksum is provided, prints a warning but continues (backward compatibility)

## Security Benefits

1. **Artifact Integrity**: Ensures the downloaded JAR matches the expected artifact by cryptographic hash
2. **Supply Chain Protection**: Protects against compromised repositories, mirrors, proxies, or MITM attacks
3. **Defense in Depth**: Even with HTTPS, adds an additional layer of verification
4. **Fail-Safe**: If verification fails, the malicious JAR is deleted and execution is prevented

## Backward Compatibility

The fix maintains backward compatibility:
- If `wrapperSha256Sum` is not present in maven-wrapper.properties, a warning is printed but execution continues
- Existing projects without the checksum property will continue to work (with a warning)
- Projects can opt-in to security by adding the checksum property

## Implementation Details

### Checksum Calculation
- Algorithm: SHA-256 (cryptographically secure)
- Format: Lowercase hexadecimal string (64 characters)
- Comparison: Case-insensitive to handle different formats

### Error Handling
- Download failures are detected before checksum verification
- Checksum mismatches result in immediate failure and cleanup
- Clear error messages indicate expected vs actual checksums for debugging

## Files Modified

1. `.mvn/wrapper/maven-wrapper.properties` - Added wrapperSha256Sum property
2. `mvnw` - Added checksum verification for Unix/Linux/macOS
3. `mvnw.cmd` - Added checksum verification for Windows
4. `MavenWrapperDownloader.java` - Added checksum verification for Java fallback

## Testing Recommendations

1. Verify successful download with correct checksum
2. Verify failure with incorrect checksum
3. Verify warning message when checksum is not provided
4. Test on Unix/Linux/macOS with both shasum and sha256sum
5. Test on Windows with PowerShell
6. Test Java fallback path when wget/curl are not available
