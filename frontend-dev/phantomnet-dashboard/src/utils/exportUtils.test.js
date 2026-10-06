/* global process */
/**
 * Automated test suite for CSV Export Utility (DEF-FOR-01)
 * Validates RFC 4180 CSV compliance, array handling, escaping, and sections independence:
 * 1. Normal array of events
 * 2. Empty array
 * 3. Null/undefined field values
 * 4. Values containing commas
 * 5. Values containing quotes
 * 6. Values containing newline characters
 * 7. Realistic hunting event
 * 8. CSV export no longer accesses data.sections (never throws TypeError)
 */
import { exportToCSV, escapeCSVCell } from './exportUtils.js';

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

console.log('--- Testing CSV Export Utility (DEF-FOR-01) ---');

// Test 1: Normal array of events
const normalEvents = [
    { id: 1, src_ip: '192.168.1.100', protocol: 'TCP', threat_score: 85 },
    { id: 2, src_ip: '10.0.0.50', protocol: 'SSH', threat_score: 42 }
];
const csv1 = exportToCSV(normalEvents, 'Test_Normal');
assert(csv1.includes('id,src_ip,protocol,threat_score'), 'Test 1: Header row generated');
assert(csv1.includes('1,192.168.1.100,TCP,85'), 'Test 1: Row 1 generated');
assert(csv1.includes('2,10.0.0.50,SSH,42'), 'Test 1: Row 2 generated');

// Test 2: Empty array
const csv2 = exportToCSV([], 'Test_Empty');
assertEqual(csv2, '', 'Test 2: Empty array returns empty string without error');

// Test 3: Null/undefined field values
const nullEvents = [
    { id: 1, src_ip: '10.99.1.1', payload: null, notes: undefined }
];
const csv3 = exportToCSV(nullEvents, 'Test_Nulls');
assert(csv3.includes('1,10.99.1.1,,'), 'Test 3: Null and undefined serialized as empty cells');

// Test 4: Values containing commas
const commaEvents = [
    { id: 1, desc: 'SYN, ACK scan detected' }
];
const csv4 = exportToCSV(commaEvents, 'Test_Comma');
assert(csv4.includes('1,"SYN, ACK scan detected"'), 'Test 4: Comma wrapped in quotes');

// Test 5: Values containing quotes
const quoteEvents = [
    { id: 1, query: 'SELECT * FROM "users"' }
];
const csv5 = exportToCSV(quoteEvents, 'Test_Quotes');
assert(csv5.includes('1,"SELECT * FROM ""users"""'), 'Test 5: Double quotes escaped to double double-quotes');

// Test 6: Values containing newline characters
const newlineEvents = [
    { id: 1, log: "line 1\nline 2\r\nline 3" }
];
const csv6 = exportToCSV(newlineEvents, 'Test_Newlines');
assert(csv6.includes('1,"line 1\nline 2\r\nline 3"'), 'Test 6: Multiline string wrapped in quotes');

// Test 7: Realistic hunting event
const huntingEvents = [
    {
        Time: '2026-10-04T09:32:00.000Z',
        Source: '198.51.100.44',
        Destination: '10.0.0.50:2222',
        Protocol: 'SSH',
        'Threat Level': 'HIGH',
        'Attack Type': 'Brute Force',
        'Threat Score': 75,
        'Is Malicious': 'Yes'
    }
];
const csv7 = exportToCSV(huntingEvents, 'Hunting_Report');
assert(csv7.includes('Time,Source,Destination,Protocol,Threat Level,Attack Type,Threat Score,Is Malicious'), 'Test 7: Realistic hunting headers present');
assert(csv7.includes('2026-10-04T09:32:00.000Z,198.51.100.44,10.0.0.50:2222,SSH,HIGH,Brute Force,75,Yes'), 'Test 7: Realistic hunting event row present');

// Test 8: CSV export no longer accesses data.sections (never throws TypeError on flat array or missing sections)
let threwError = false;
try {
    exportToCSV([{ a: 1, b: 2 }]);
} catch (e) {
    threwError = true;
    console.error(e);
}
assert(!threwError, 'Test 8: Flat event array never throws TypeError from data.sections');

// Test 9: Backward compatibility with ReportBuilder structured sections format
const structuredReport = {
    title: 'Executive Security Report',
    generated_at: '2026-10-04',
    sections: {
        summary: { total_alerts: 10, risk: 'Medium' }
    }
};
const csv9 = exportToCSV(structuredReport, 'Structured_Report');
assert(csv9.includes('Report Title,Executive Security Report'), 'Test 9: Structured report title supported');
assert(csv9.includes('SUMMARY'), 'Test 9: Structured report section header supported');
assert(csv9.includes('total_alerts,10'), 'Test 9: Structured report key-value supported');

// Test 10: Null and undefined input safely returns empty string without error
const csvNull = exportToCSV(null, 'Test_Null');
const csvUndefined = exportToCSV(undefined, 'Test_Undefined');
assertEqual(csvNull, '', 'Test 10A: null input returns empty string');
assertEqual(csvUndefined, '', 'Test 10B: undefined input returns empty string');

// Test 11: Multiline complex payload with quotes, commas, and CRLF
const complexPayloadEvents = [
    {
        id: 101,
        src_ip: '192.168.1.50',
        payload: 'POST /login HTTP/1.1\r\nHost: target.local\r\nContent-Type: application/json\r\n\r\n{"user":"admin","hash":"a,b,c\\"test\\""}'
    }
];
const csv11 = exportToCSV(complexPayloadEvents, 'Complex_Payload');
assert(csv11.includes('id,src_ip,payload'), 'Test 11: Headers present');
assert(csv11.includes('101,192.168.1.50,"POST /login HTTP/1.1'), 'Test 11: Complex payload safely quoted');

// Test 12: RFC 4180 CRLF line ending compliance
assert(csv1.includes('\r\n'), 'Test 12: RFC 4180 CRLF line endings present');

console.log(`\nResults: ${passed} passed, ${failed} failed.`);
if (failed > 0) {
    process.exit(1);
} else {
    console.log('✅ All exportUtils tests passed cleanly.');
}
