# Release Notes: Proxy Cache Scan-Before-Serve

## Overview

This release introduces the **scan-before-serve** feature for proxy cache projects with vulnerability prevention enabled. Previously, Harbor proxy cache would serve images immediately and scan them in the background, allowing vulnerable images to be pulled before scanning completed. This behavior bypassed the "Prevent vulnerable images from running" security policy.

## What Changed

### New Behavior for Proxy Cache Projects

When **both** of the following conditions are met:
1. Project is a **proxy cache project** (has upstream registry configured)
2. Project has **"Prevent vulnerable images from running"** enabled (`prevent_vul=true`)

Harbor now implements scan-before-serve:
- **First Pull Request**: Image is fetched from upstream and cached, but **NOT served immediately**
  - Client receives HTTP 412 Precondition Failed error
  - Error message: "Artifact {name}:{tag} is being cached and scanned. Please retry in a moment."
  - Background: Image is cached to local registry and scan is triggered (if auto-scan enabled)

- **Subsequent Pull Requests** (after caching/scanning completes):
  - If scan is still in progress: HTTP 412 with message "Image is being scanned, please retry later"
  - If scan failed: HTTP 412 with message "Image scan {status}, cannot be pulled"
  - If scan succeeded but image is vulnerable: HTTP 412 with vulnerability details
  - If scan succeeded and image is safe: HTTP 200, image is served

### Enhanced Error Messages

Vulnerability prevention now provides more actionable error messages based on scan status:

| Scan Status | Error Message | Action Required |
|-------------|---------------|-----------------|
| **No scan report** | "Current image without vulnerability scanning cannot be pulled" | Enable auto-scan or manually trigger scan |
| **Pending/Running/Scheduled** | "Image is being scanned, please retry later" | Wait for scan to complete (typically 10-60 seconds) |
| **Error/Stopped** | "Image scan {status}, cannot be pulled" | Check scanner configuration, retry scan manually |
| **Success (vulnerable)** | "Current image with N vulnerabilities cannot be pulled" | Review CVE allowlist or use different image version |
| **Success (safe)** | Image is served | - |

## Impact on User Workflows

### Breaking Changes

#### Proxy Cache with Vulnerability Prevention
**Before**: Images pulled immediately on first request, potential security gap
```bash
$ docker pull harbor.example.com/proxy-cache/library/nginx:latest
# ✓ Image pulled successfully (even if vulnerable, scan happens later)
```

**After**: First pull is blocked, retry required
```bash
$ docker pull harbor.example.com/proxy-cache/library/nginx:latest
# ✗ Error: Artifact proxy-cache/library/nginx:latest is being cached and scanned. Please retry in a moment.

# Wait 10-30 seconds, then retry:
$ docker pull harbor.example.com/proxy-cache/library/nginx:latest
# If scan pending: "Image is being scanned, please retry later"
# If scan complete and safe: ✓ Image pulled successfully
# If vulnerable: ✗ Error with vulnerability details
```

### Non-Breaking Scenarios

The following scenarios are **NOT affected** and work exactly as before:
- Regular (non-proxy) projects with vulnerability prevention
- Proxy cache projects **without** vulnerability prevention enabled
- Proxy cache with vulnerability prevention **disabled** (`prevent_vul=false`)
- Subsequent pulls of already-cached images
- Blob pulls (only manifest pulls are affected)
- Scanner/Cosign signature pulls (automatically exempted)

## User Migration Guide

### For Proxy Cache Users with Vulnerability Prevention

1. **Update CI/CD Pipelines**
   - Add retry logic for image pulls from proxy cache projects
   - Expect HTTP 412 on first pull of new images
   - Recommended retry: 2-3 attempts with 15-30 second delays

   Example with Docker:
   ```bash
   #!/bin/bash
   IMAGE="harbor.example.com/proxy-cache/library/nginx:latest"
   MAX_RETRIES=3
   RETRY_DELAY=20

   for i in $(seq 1 $MAX_RETRIES); do
     if docker pull "$IMAGE"; then
       echo "Pull succeeded"
       exit 0
     fi
     echo "Pull failed, attempt $i of $MAX_RETRIES"
     [ $i -lt $MAX_RETRIES ] && sleep $RETRY_DELAY
   done

   echo "Pull failed after $MAX_RETRIES attempts"
   exit 1
   ```

2. **Enable Auto-Scan**
   - Ensure auto-scan is enabled on proxy cache projects
   - Without auto-scan, images will be blocked indefinitely
   - Navigate to: Project → Configuration → Automatically scan images on push → ON

3. **Configure Scanner**
   - Verify scanner (Trivy/Clair) is configured and healthy
   - Check scanner connectivity: Administration → Interrogation Services
   - Scanner downtime will prevent image pulls in proxy cache projects with prevention enabled

4. **Monitor Scan Duration**
   - Typical scan time: 10-60 seconds depending on image size
   - Large images (>1GB) may take longer
   - Plan CI/CD timeouts accordingly

### For New Deployments

1. **Recommended Setup for Proxy Cache with Security**:
   ```
   Project Settings:
   ├── Proxy Cache: Enabled
   ├── Prevent vulnerable images: Enabled
   ├── Vulnerability severity: High (or as needed)
   ├── Automatically scan images: Enabled
   └── CVE allowlist: Configure as needed
   ```

2. **Pre-populate Cache** (Optional):
   - Manually pull critical images before production use
   - This triggers caching and scanning ahead of time
   - Subsequent pulls will be immediate

3. **Testing**:
   ```bash
   # Test the scan-before-serve flow:
   docker pull harbor.example.com/proxy-cache/library/alpine:latest
   # Expected: Error on first pull

   # Wait 20 seconds
   sleep 20

   # Retry
   docker pull harbor.example.com/proxy-cache/library/alpine:latest
   # Expected: Success (alpine is typically clean)
   ```

## Configuration Options

### Project-Level Settings

| Setting | Location | Effect |
|---------|----------|--------|
| **Prevent vulnerable images** | Project → Configuration | Enable/disable scan-before-serve |
| **Vulnerability severity** | Project → Configuration | Minimum severity to block (None/Low/Medium/High/Critical) |
| **Automatically scan images** | Project → Configuration | Auto-trigger scans on cache (required for scan-before-serve) |
| **CVE allowlist** | Project → Configuration | Exempt specific CVEs from blocking |

### System-Level Settings

| Setting | Location | Effect |
|---------|----------|--------|
| **Scanner configuration** | Administration → Interrogation Services | Configure Trivy/Clair scanner |
| **Scanner health** | Administration → Interrogation Services | Monitor scanner status |

## Technical Details

### Middleware Execution Order

For manifest GET requests:
1. **Proxy Middleware**: Checks if manifest cached, triggers caching if needed
2. **Content Trust Middleware**: Verifies signatures (if enabled)
3. **Vulnerable Middleware**: Checks scan status and vulnerabilities
4. **Handler**: Serves manifest if all checks pass

### Caching Behavior

- **Async Caching**: Manifest caching happens in background (unchanged)
- **Deduplication**: Multiple concurrent requests for same image are deduplicated
- **Retry Safety**: Multiple caching attempts for same artifact are prevented
- **Scan Trigger**: PUSH event triggers scan automatically (if auto-scan enabled)

### Error Codes

| HTTP Status | Scenario |
|-------------|----------|
| **412 Precondition Failed** | Image being cached/scanned, or fails vulnerability check |
| **404 Not Found** | Image not found in upstream registry |
| **429 Too Many Requests** | Exceeded max upstream registry connections |
| **500 Internal Server Error** | Scanner error or internal failure |

## Known Limitations

1. **First Pull Delay**: First pull of new image will fail and require retry (this is by design)
2. **Scan Duration**: Scan must complete before image can be pulled (10-60+ seconds)
3. **Scanner Dependency**: Scanner downtime blocks new image pulls in protected proxy projects
4. **No Synchronous Option**: Caching is async; cannot wait for scan completion in single request
5. **Manifest Lists**: Multi-arch manifest lists skip vulnerability checking (existing behavior)

## Troubleshooting

### "Artifact is being cached and scanned. Please retry in a moment."
- **Cause**: First pull of new image
- **Solution**: Wait 15-30 seconds and retry pull

### "Image is being scanned, please retry later"
- **Cause**: Scan in progress
- **Solution**: Wait for scan to complete (check Harbor UI → Artifacts → Scan status)

### "Image scan Error, cannot be pulled"
- **Cause**: Scanner failure or configuration issue
- **Solution**: Check Administration → Interrogation Services, verify scanner is healthy

### Images never become pullable
- **Check 1**: Is auto-scan enabled? (Project → Configuration)
- **Check 2**: Is scanner healthy? (Administration → Interrogation Services)
- **Check 3**: Check artifact scan status in Harbor UI

### CI/CD pipeline failures
- **Solution**: Add retry logic with delays (see migration guide above)
- **Alternative**: Disable vulnerability prevention during testing, enable in production

## Rollback Plan

To revert to previous behavior:

1. **Per-Project**: Disable "Prevent vulnerable images from running"
   - Navigate to: Project → Configuration
   - Toggle OFF: "Prevent vulnerable images from running"

2. **System-Wide**: Revert to previous Harbor version
   - This feature is backward compatible; old behavior available via configuration

## Security Implications

### Improved Security
- ✅ Proxy cache projects now respect vulnerability prevention policy
- ✅ Vulnerable images cannot be pulled before scanning completes
- ✅ Closes security gap where vulnerable images could bypass policy
- ✅ Better error messages help users understand security blocks

### Trade-offs
- ⚠️ First pull requires retry (operational overhead)
- ⚠️ Scanner downtime impacts image availability
- ⚠️ Increased reliance on scanner health

## Frequently Asked Questions

**Q: Will this affect my existing proxy cache projects?**
A: Only if you have "Prevent vulnerable images from running" enabled. Projects without this setting are unaffected.

**Q: Can I disable this behavior?**
A: Yes, disable "Prevent vulnerable images from running" in project settings to restore immediate serving.

**Q: How long should I wait between retries?**
A: Typically 15-30 seconds. Large images may require 60+ seconds.

**Q: What if my scanner is temporarily down?**
A: New image pulls will fail in proxy cache projects with prevention enabled. Already-scanned images can still be pulled.

**Q: Does this affect performance?**
A: First pull has added latency (caching + scan time). Subsequent pulls are unaffected.

**Q: Can I pre-populate the cache?**
A: Yes, manually pull images before production use to trigger caching and scanning ahead of time.

## Related Documentation

- [Harbor Vulnerability Scanning](https://goharbor.io/docs/latest/administration/vulnerability-scanning/)
- [Proxy Cache Projects](https://goharbor.io/docs/latest/administration/configure-proxy-cache/)
- [CVE Allowlists](https://goharbor.io/docs/latest/working-with-projects/project-configuration/configure-cve-allowlists/)

## Support

For issues or questions:
- GitHub Issues: https://github.com/goharbor/harbor/issues
- Slack: #harbor-users on CNCF Slack

## Version Information

- **Feature Introduced**: Harbor Next (this release)
- **Affected Components**: Proxy cache middleware, Vulnerability middleware
- **Database Changes**: None
- **API Changes**: Error response codes and messages enhanced
