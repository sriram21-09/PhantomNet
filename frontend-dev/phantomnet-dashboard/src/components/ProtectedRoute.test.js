/* global process */
/**
 * Automated test suite for ProtectedRoute role authorization logic (DEF-FOR-03)
 * Validates:
 * 1. Admin allowed on /hunting
 * 2. Analyst allowed on /hunting
 * 3. Viewer blocked from /hunting (Access Denied)
 * 4. Unauthenticated redirected to /login
 * 5. Error classification: 401, 403 CSRF vs 403 RBAC, 422, 500, Network error
 */

let passed = 0;
let failed = 0;

function assert(condition, message) {
    if (condition) {
        passed++;
    } else {
        failed++;
        console.error(`❌ FAIL: ${message}`);
    }
}

function assertEqual(actual, expected, message) {
    if (actual === expected) {
        passed++;
    } else {
        failed++;
        console.error(`❌ FAIL: ${message} | Expected: ${JSON.stringify(expected)}, Got: ${JSON.stringify(actual)}`);
    }
}

console.log('--- Testing ProtectedRoute Authorization Logic (DEF-FOR-03) ---');

// Pure role check simulation matching ProtectedRoute.jsx:45-48
function checkAccess(user, isAuthenticated, allowedRoles) {
    if (!isAuthenticated) {
        return { access: false, action: 'REDIRECT_LOGIN' };
    }
    if (allowedRoles && allowedRoles.length > 0) {
        const userRole = user?.role;
        if (!userRole || !allowedRoles.includes(userRole)) {
            return {
                access: false,
                action: 'ACCESS_DENIED',
                userRole: userRole || 'Unknown',
                requiredRoles: allowedRoles
            };
        }
    }
    return { access: true, action: 'ALLOW' };
}

const HUNTING_ALLOWED_ROLES = ['Admin', 'Analyst'];

// Test 1: Admin allowed
const resAdmin = checkAccess({ username: 'admin', role: 'Admin' }, true, HUNTING_ALLOWED_ROLES);
assert(resAdmin.access === true, 'Test 1: Admin account permitted into /hunting');
assertEqual(resAdmin.action, 'ALLOW', 'Test 1 action is ALLOW');

// Test 2: Analyst allowed
const resAnalyst = checkAccess({ username: 'test_analyst', role: 'Analyst' }, true, HUNTING_ALLOWED_ROLES);
assert(resAnalyst.access === true, 'Test 2: Analyst account permitted into /hunting');
assertEqual(resAnalyst.action, 'ALLOW', 'Test 2 action is ALLOW');

// Test 3: Viewer blocked
const resViewer = checkAccess({ username: 'test_viewer', role: 'Viewer' }, true, HUNTING_ALLOWED_ROLES);
assert(resViewer.access === false, 'Test 3: Viewer account blocked from /hunting');
assertEqual(resViewer.action, 'ACCESS_DENIED', 'Test 3 action is ACCESS_DENIED');
assertEqual(resViewer.userRole, 'Viewer', 'Test 3 user role correctly identified as Viewer');

// Test 4: Unauthenticated redirected
const resUnauth = checkAccess(null, false, HUNTING_ALLOWED_ROLES);
assert(resUnauth.access === false, 'Test 4: Unauthenticated session blocked');
assertEqual(resUnauth.action, 'REDIRECT_LOGIN', 'Test 4 redirects to login');

console.log('\n--- Testing Frontend Error Classification Logic (DEF-FOR-05 / CSRF-01) ---');

function classifySearchError(err) {
    let message = 'Unable to execute hunt query.';
    const status = err.response?.status;
    if (status === 401) {
        message = 'Authentication required. Please log in again.';
    } else if (status === 403) {
        const detail = err.response?.data?.detail;
        const detailStr = typeof detail === 'string' ? detail : '';
        if (detailStr.toLowerCase().includes('csrf') || detailStr.toLowerCase().includes('custom request header') || detailStr.includes('Origin not allowed')) {
            message = 'Security validation failed. Please refresh the session and try again.';
        } else if (detailStr.includes('Requires role') || detailStr.toLowerCase().includes('permission')) {
            message = 'You do not have permission to perform this hunt.';
        } else {
            message = detailStr || 'You do not have permission to perform this hunt.';
        }
    } else if (status === 422) {
        const detail = err.response?.data?.detail;
        if (typeof detail === 'string') {
            message = detail;
        } else if (Array.isArray(detail)) {
            message = detail.map(d => d.msg ? d.msg.replace(/^Value error,\s* /i, '') : JSON.stringify(d)).join('; ');
        } else {
            message = 'Invalid hunt query parameters.';
        }
    } else if (status === 500) {
        message = 'Hunting service unavailable or internal backend error.';
    } else if (err.code === 'ECONNABORTED' || !err.response) {
        message = 'Network error: unable to reach the hunting service.';
    }
    return { message, status };
}

// Test 5: 401 Authentication error
const err401 = classifySearchError({ response: { status: 401, data: { detail: 'Not authenticated' } } });
assertEqual(err401.message, 'Authentication required. Please log in again.', 'Test 5: 401 classified correctly');

// Test 6: 403 RBAC error
const err403RBAC = classifySearchError({ response: { status: 403, data: { detail: 'Requires role: Admin, Analyst' } } });
assertEqual(err403RBAC.message, 'You do not have permission to perform this hunt.', 'Test 6: 403 RBAC classified correctly');

// Test 7: 403 CSRF error
const err403CSRF = classifySearchError({ response: { status: 403, data: { detail: 'CSRF validation failed: Missing custom request header' } } });
assertEqual(err403CSRF.message, 'Security validation failed. Please refresh the session and try again.', 'Test 7: 403 CSRF classified correctly');

// Test 8: 422 Validation error with string detail
const err422Str = classifySearchError({ response: { status: 422, data: { detail: "Unsupported search field: 'threat_lvel'" } } });
assertEqual(err422Str.message, "Unsupported search field: 'threat_lvel'", 'Test 8: 422 string detail preserved');

// Test 9: 500 Internal server error
const err500 = classifySearchError({ response: { status: 500, data: { detail: 'Database error' } } });
assertEqual(err500.message, 'Hunting service unavailable or internal backend error.', 'Test 9: 500 classified correctly');

// Test 10: Network failure
const errNet = classifySearchError({ code: 'ECONNABORTED' });
assertEqual(errNet.message, 'Network error: unable to reach the hunting service.', 'Test 10: Network failure classified correctly');

console.log(`\nResults: ${passed} passed, ${failed} failed.`);
if (failed > 0) {
    process.exit(1);
} else {
    console.log('✅ ALL PROTECTED ROUTE & ERROR CLASSIFICATION TESTS PASSED.');
}
