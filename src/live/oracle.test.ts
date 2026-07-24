import { test } from "node:test";
import assert from "node:assert/strict";
import { CallbackOracle } from "./oracle.js";

test("waitForCallback resolves when a real HTTP request bearing the nonce arrives", async () => {
  const oracle = new CallbackOracle();
  await oracle.start();
  try {
    const nonce = oracle.newNonce("test");
    const url = oracle.callbackUrl(nonce);
    assert.match(url, new RegExp(`^http://127\\.0\\.0\\.1:\\d+/cb/${nonce}$`));

    const waiter = oracle.waitForCallback(nonce, 2_000);
    const response = await fetch(url);
    assert.equal(response.status, 200);

    const event = await waiter;
    assert.ok(event);
    assert.equal(event?.nonce, nonce);
    assert.equal(event?.method, "GET");
    assert.equal(event?.remoteAddress, "127.0.0.1");
  } finally {
    await oracle.stop();
  }
});

test("waitForCallback resolves to null when no callback arrives before the timeout", async () => {
  const oracle = new CallbackOracle();
  await oracle.start();
  try {
    const nonce = oracle.newNonce("never-called");
    const event = await oracle.waitForCallback(nonce, 100);
    assert.equal(event, null);
  } finally {
    await oracle.stop();
  }
});

test("a callback already received before waitForCallback is called still resolves immediately", async () => {
  const oracle = new CallbackOracle();
  await oracle.start();
  try {
    const nonce = oracle.newNonce("early");
    const url = oracle.callbackUrl(nonce);
    const response = await fetch(url);
    assert.equal(response.status, 200);

    const event = await oracle.waitForCallback(nonce, 1_000);
    assert.ok(event);
    assert.equal(event?.nonce, nonce);
  } finally {
    await oracle.stop();
  }
});

test("callbacks for one nonce do not resolve a wait on a different nonce", async () => {
  const oracle = new CallbackOracle();
  await oracle.start();
  try {
    const nonceA = oracle.newNonce("a");
    const nonceB = oracle.newNonce("b");
    const waiterB = oracle.waitForCallback(nonceB, 300);
    await fetch(oracle.callbackUrl(nonceA));
    const eventB = await waiterB;
    assert.equal(eventB, null);
  } finally {
    await oracle.stop();
  }
});

test("newNonce produces distinct, path-safe nonces", () => {
  const oracle = new CallbackOracle();
  const a = oracle.newNonce("run_diagnostic-hostname");
  const b = oracle.newNonce("run_diagnostic-hostname");
  assert.notEqual(a, b);
  assert.match(a, /^[a-zA-Z0-9_-]+$/);
});
