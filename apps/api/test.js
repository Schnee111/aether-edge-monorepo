import test from "node:test"; import assert from "node:assert"; import { createApp } from "./index.js"; test("api creates app", () => { assert.strictEqual(typeof createApp, "function"); });
