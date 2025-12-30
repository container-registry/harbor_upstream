# Implementation Plan: Proxy Cache Scan-Before-Serve

## Problem Statement

Currently, Harbor proxy cache serves images immediately and scans them in the background. This means the "Prevent vulnerable images from running" setting doesn't work for proxy cache - clients receive images before scanning completes.

## Solution

Change proxy cache flow when `prevent_vul=true`:
- **Before:** Stream to client → Cache in background → Scan in background
- **After:** Cache synchronously → Scan triggered → Check status → Serve or block

## Scope

**What changes:**
- Proxy manifest middleware: Add synchronous caching path
- Vulnerable middleware: Better error messages for scan states

**What stays the same:**
- Blob handling (no changes)
- Webhook system (no changes)
- Manifest list handling (skip checking)
- When prevent_vul=false (current behavior)

## Requirements

1. Only affect proxy cache when `prevent_vul=true`
2. Return immediate error (no waiting/blocking)
3. Simple, clear error messages
4. Block manifests only (not blobs)
5. TDD approach (tests first)
6. Short conventional commits (no AI credits)

## Files to Change

### 1. CREATE: `vulnerable_tdd_test.go`

**Location:** `/home/bupd/code/OSS/Harbr/next-proxy-scan-serve/src/server/middleware/vulnerable/vulnerable_tdd_test.go`

**Purpose:** Test enhanced scan status blocking

**Tests:**
- No scan report + prevent_vul=true → Block
- Scan pending/running → Block with "scanning" error
- Scan failed → Block with "scan failed" error
- No scan + prevent_vul=false → Allow
- Scanned below threshold → Allow
- Scanned above threshold → Block

### 2. CREATE: `proxy_tdd_test.go`

**Location:** `/home/bupd/code/OSS/Harbr/next-proxy-scan-serve/src/server/middleware/repoproxy/proxy_tdd_test.go`

**Purpose:** Test synchronous caching logic

**Tests:**
- prevent_vul=false → Stream immediately (current behavior)
- prevent_vul=true + not cached → Cache synchronously first
- Manifest already cached → Use local
- Non-proxy project → Current behavior
- Manifest list → Skip checking

### 3. MODIFY: `vulnerable.go`

**Location:** `/home/bupd/code/OSS/Harbr/next-proxy-scan-serve/src/server/middleware/vulnerable/vulnerable.go`

**Lines:** 84-121 (scan status checking section)

**Change 1: Handle missing scan report**

When no scan report exists:
- Check if artifact is scannable
- If not scannable → Block with "scanner unavailable" error
- If scannable but auto-scan off → "Auto-scan disabled, enable it or scan manually"
- If scannable and auto-scan on → "Scan queued, retry later"

**Change 2: Check scan status**

Before checking vulnerabilities:
- If scan Pending/Running/Scheduled → "Image is being scanned, retry later"
- If scan Failed/Error/Stopped → "Image scan [status], cannot pull"
- If scan Success → Continue to vulnerability check (existing code)

### 4. MODIFY: `proxy.go`

**Location:** `/home/bupd/code/OSS/Harbr/next-proxy-scan-serve/src/server/middleware/repoproxy/proxy.go`

**Function:** `handleManifest` (lines 205-281)

**Change: Add synchronous caching path**

In `handleManifest`, after checking `UseLocalManifest`:

**If manifest NOT cached:**
- Check if `p.VulPrevented()` is true
- If YES → Call new function `cacheThenServeManifest()`
- If NO → Current behavior (proxyManifestGet/Head)

**New function: `cacheThenServeManifest()`**

Add after line 297:
1. Fetch manifest from remote
2. Push to local registry (synchronous) - this triggers PUSH event
3. PUSH event handler triggers scan (if auto-scan enabled)
4. Write manifest to response
5. Vulnerable middleware (next in chain) checks scan status
6. If scan missing/pending → Block
7. If scan passed → Client receives manifest

## Implementation Steps (TDD)

### Step 1: Write Vulnerable Middleware Tests

Create `vulnerable_tdd_test.go` with all test cases → Run → FAIL

### Step 2: Implement Vulnerable Middleware Changes

Modify `vulnerable.go` to handle scan states → Run tests → PASS

**Commit:** `test: add tests for blocking unscanned images`
**Commit:** `feat: block unscanned and scanning images when prevention enabled`

### Step 3: Write Proxy Middleware Tests

Create `proxy_tdd_test.go` with all test cases → Run → FAIL

### Step 4: Implement Proxy Middleware Changes

Add `cacheThenServeManifest` and modify `handleManifest` → Run tests → PASS

**Commit:** `test: add tests for synchronous proxy cache`
**Commit:** `feat: cache proxy manifests synchronously when prevention enabled`

### Step 5: Integration Testing

- Run full test suite
- Manual testing with real proxy project
- Test all edge cases

**Commit:** `test: add integration tests for proxy cache scan enforcement`

## Edge Cases Handled

| Scenario | Behavior | Location |
|----------|----------|----------|
| Auto-scan off + prevent_vul on | Block with "enable auto-scan" error | vulnerable.go |
| Scanner offline/unavailable | Block new images, allow scanned images | vulnerable.go IsScannable() |
| Cached but not scanned | Block, trigger scan if auto-scan on | vulnerable.go |
| Manifest list (multi-arch) | Skip (existing behavior) | vulnerable.go lines 107-115 |
| Scanner/Cosign pulls | Skip check (existing behavior) | vulnerable.go lines 72-79 |
| Blob pulls | No changes (not checked) | No changes |
| Race: scan completes mid-check | No issue, middleware sees result | No special handling |
| Concurrent pulls | Deduplicated by inflightChecker | Existing code |

## Files Summary

**Create (tests first):**
1. `src/server/middleware/vulnerable/vulnerable_tdd_test.go`
2. `src/server/middleware/repoproxy/proxy_tdd_test.go`

**Modify (implementation):**
3. `src/server/middleware/vulnerable/vulnerable.go` (lines 84-121)
4. `src/server/middleware/repoproxy/proxy.go` (lines 205-281 + new function)

**Update (additional tests):**
5. `src/server/middleware/vulnerable/vulnerable_test.go`

## Success Criteria

- ✅ prevent_vul=true → Cache synchronously before serving
- ✅ Unscanned images → Block with clear error
- ✅ Scanning images → Block with "retry later"
- ✅ Failed scans → Block with error
- ✅ prevent_vul=false → No regression
- ✅ All tests pass
- ✅ Clear error messages

## Commits

1. `test: add tests for blocking unscanned images`
2. `feat: block unscanned and scanning images when prevention enabled`
3. `test: add tests for synchronous proxy cache`
4. `feat: cache proxy manifests synchronously when prevention enabled`
5. `test: add integration tests for proxy cache scan enforcement`

(Short, conventional, no AI credits)
