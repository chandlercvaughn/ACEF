/**
 * Cross-language parity (DUP-KEY-IJSON-DETERMINISM @905302e): the TS SDK must
 * reject duplicate object member names in the hash domain too (RFC 7493 §2.3),
 * mirroring Python's acef.integrity._reject_duplicate_keys. JS JSON.parse is
 * last-wins, so without this the TS exporter could hash {"a":1,"a":2} identically
 * to {"a":2}. Mirrors tests/unit/test_duplicate_member_names.py.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { assertNoDuplicateMemberNames } from "../src/integrity.js";

test("rejects a top-level duplicate member name", () => {
    assert.throws(() => assertNoDuplicateMemberNames('{"a":1,"a":2}'), /duplicate object member name/);
});

test("rejects a nested duplicate member name", () => {
    assert.throws(() => assertNoDuplicateMemberNames('{"x":{"a":1,"a":2}}'), /duplicate object member name/);
});

test("rejects a duplicate inside an array element", () => {
    assert.throws(() => assertNoDuplicateMemberNames('{"items":[{"k":1,"k":2}]}'), /duplicate object member name/);
});

test("rejects a duplicate where one key uses a unicode escape", () => {
    // "a" and "a" decode to the same key.
    assert.throws(() => assertNoDuplicateMemberNames('{"a":1,"\\u0061":2}'), /duplicate object member name/);
});

test("accepts unique members, including the same name at different object levels", () => {
    assert.doesNotThrow(() => assertNoDuplicateMemberNames('{"a":1,"b":{"a":2},"c":[1,2,{"a":3}]}'));
});

test("accepts a value string that equals a key name (not a duplicate key)", () => {
    // The string value "a" must not be mistaken for a second "a" key.
    assert.doesNotThrow(() => assertNoDuplicateMemberNames('{"a":"a","b":"a"}'));
});

test("accepts a key whose VALUE string contains braces and colons", () => {
    assert.doesNotThrow(() => assertNoDuplicateMemberNames('{"a":"{\\"x\\":1,\\"x\\":2}","b":2}'));
});
