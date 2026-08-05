import { strict as assert } from "node:assert";
import { afterEach, describe, it } from "node:test";
import { DENY_MESSAGE } from "../src/enforce.js";
import {
  MAX_CONCURRENT_OBSERVATIONS,
  MAX_OBSERVED_TOOL_NAME_CHARS,
  MAX_QUEUED_OBSERVATIONS,
  createBlockedUnmappedObserver,
  observeBlockedUnmapped,
} from "../src/observe.js";
import { settle, startHarness, until, type Harness } from "./helpers.js";

const ENV = {
  VINCTOR_ENDPOINT: "http://vinctor.test/",
  VINCTOR_PEP_KEY: "pep_test",
  VINCTOR_SUBJECT_TOKEN: "vat_test",
  VINCTOR_WORKSPACE_ID: "ws_test",
  VINCTOR_AGENT_ID: "agent_test",
};

const TOOL_CALL = JSON.stringify({
  jsonrpc: "2.0",
  id: 41,
  method: "tools/call",
  params: {
    name: "execute_shell",
    arguments: { command: "git status && rm -rf x" },
  },
});

const EXPECTED_DENY = JSON.stringify({
  jsonrpc: "2.0",
  id: 41,
  error: { code: -32000, message: DENY_MESSAGE },
});

let harness: Harness;
afterEach(async () => {
  if (harness) await harness.stop();
});

describe("blocked-unmapped observation", () => {
  it("denies prototype-chain tool names locally and observes without a PDP call", async () => {
    const urls: string[] = [];
    harness = startHarness(ENV, {
      fetchFn: async (input) => {
        urls.push(String(input));
        return new Response("down", { status: 503 });
      },
    });
    const names = [
      "filesystem__toString",
      "github__toString",
      "slack__valueOf",
      "filesystem____proto__",
    ];
    for (const [index, name] of names.entries()) {
      harness.send(
        JSON.stringify({
          jsonrpc: "2.0",
          id: index + 1,
          method: "tools/call",
          params: { name, arguments: { path: "/root/.ssh/id_rsa" } },
        }),
      );
    }

    await until(() => harness.clientLines.length === names.length, "prototype-name denies");
    await until(() => urls.length === names.length, "prototype-name observations");
    assert.deepEqual(
      harness.clientLines.map((line) => JSON.parse(line).id),
      [1, 2, 3, 4],
    );
    assert.ok(urls.every((url) => url === "http://vinctor.test/v1/observe"));
    assert.deepEqual(harness.serverLog(), []);
  });

  it("attempts a redacted /v1/observe POST and still denies locally", async () => {
    let url = "";
    let headers: Headers | null = null;
    let body: Record<string, unknown> | null = null;
    const fakeFetch: typeof fetch = async (input, init) => {
      url = String(input);
      headers = new Headers(init?.headers);
      body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response("down", { status: 503 });
    };
    harness = startHarness(ENV, { fetchFn: fakeFetch });
    harness.send(TOOL_CALL);

    await until(() => harness.clientLines.length >= 1, "unmapped deny response");
    await until(() => body !== null, "blocked-unmapped observe attempt");
    assert.equal(harness.clientLines[0], EXPECTED_DENY);
    assert.equal(url, "http://vinctor.test/v1/observe");
    assert.equal(headers!.get("x-pep-key"), "pep_test");
    assert.equal(headers!.get("x-subject-token"), "vat_test");
    assert.deepEqual(body, {
      workspace_id: "ws_test",
      agent_id: "agent_test",
      classification: "unmapped",
      outcome: "blocked_unmapped",
      tool_name: "execute_shell",
    });
    assert.ok(!JSON.stringify(body).includes("git status"));
    assert.deepEqual(harness.serverLog(), []);
  });

  it("an observe exception does not propagate or change the local deny", async () => {
    harness = startHarness(ENV, {
      fetchFn: async () => { throw new Error("observe unavailable"); },
    });
    harness.send(TOOL_CALL);

    await until(() => harness.clientLines.length >= 1, "unmapped deny after observe failure");
    assert.equal(harness.clientLines[0], EXPECTED_DENY);
    assert.deepEqual(harness.serverLog(), []);
  });

  it("uses a bounded pool instead of letting one decoy suppress every other audit", async () => {
    let calls = 0;
    const releases: Array<(response: Response) => void> = [];
    harness = startHarness(ENV, {
      fetchFn: async () => {
        calls += 1;
        return await new Promise<Response>((resolve) => releases.push(resolve));
      },
    });
    for (let index = 0; index < 500; index += 1) {
      harness.send(`{"jsonrpc":"2.0","method":"vendor/unknown-${index}"}`);
    }

    await until(
      () => calls === MAX_CONCURRENT_OBSERVATIONS,
      "bounded blocked-unmapped observation pool",
    );
    await settle(100);
    assert.equal(calls, MAX_CONCURRENT_OBSERVATIONS);
    const expected = MAX_CONCURRENT_OBSERVATIONS + MAX_QUEUED_OBSERVATIONS;
    for (let index = 0; index < expected; index += 1) {
      await until(() => releases.length > index, `queued observation ${index}`);
      releases[index]!(new Response(null, { status: 204 }));
    }
    await settle(50);
    assert.equal(calls, expected);
  });

  it("eventually observes a distinct call after a decoy burst", async () => {
    const observed: string[] = [];
    harness = startHarness(ENV, {
      fetchFn: async (_input, init) => {
        const body = JSON.parse(String(init?.body)) as { tool_name: string };
        observed.push(body.tool_name);
        await new Promise((resolve) => setTimeout(resolve, 10));
        return new Response(null, { status: 204 });
      },
    });
    for (let index = 0; index < 40; index += 1) {
      harness.send(`{"jsonrpc":"2.0","method":"vendor/decoy-${index}"}`);
    }
    harness.send('{"jsonrpc":"2.0","method":"vendor/real-sensitive-call"}');

    await until(
      () => observed.includes("vendor/real-sensitive-call"),
      "later blocked call observation",
    );
  });

  it("drops the NEWEST observation on overflow so an earlier blocked call survives", async () => {
    // Reverse of the burst test above: the sensitive call comes FIRST and the
    // decoys after it. Dropping the oldest would let an agent evict its own
    // sensitive observation with cheap locally-denied decoys — attacker-
    // selected loss of exactly the record that matters.
    const observed: string[] = [];
    const releases: Array<(response: Response) => void> = [];
    const drops: number[] = [];
    const observer = createBlockedUnmappedObserver(
      ENV,
      async (_input, init) => {
        const body = JSON.parse(String(init?.body)) as { tool_name: string };
        observed.push(body.tool_name);
        return await new Promise<Response>((resolve) => releases.push(resolve));
      },
      50,
      (dropped) => drops.push(dropped),
    );

    for (let index = 0; index < MAX_CONCURRENT_OBSERVATIONS; index += 1) {
      observer(`vendor/pool-${index}`); // saturate the in-flight pool
    }
    observer("vendor/real-sensitive-call");
    const burst = MAX_QUEUED_OBSERVATIONS + 8;
    for (let index = 0; index < burst; index += 1) observer(`vendor/decoy-${index}`);
    await settle(10);

    assert.equal(observed.length, MAX_CONCURRENT_OBSERVATIONS);
    const expectedDrops = burst - (MAX_QUEUED_OBSERVATIONS - 1);
    assert.deepEqual(
      drops,
      Array.from({ length: expectedDrops }, (_value, index) => index + 1),
    );

    for (const release of releases.splice(0)) release(new Response(null, { status: 204 }));
    await settle(20);

    assert.equal(observed[MAX_CONCURRENT_OBSERVATIONS], "vendor/real-sensitive-call");
  });

  it("reports every queue-overflow observation drop on stderr", async () => {
    const releases: Array<(response: Response) => void> = [];
    harness = startHarness(ENV, {
      fetchFn: async () => await new Promise<Response>((resolve) => releases.push(resolve)),
    });
    const sends = MAX_CONCURRENT_OBSERVATIONS + MAX_QUEUED_OBSERVATIONS + 4;
    for (let index = 0; index < sends; index += 1) {
      harness.send(`{"jsonrpc":"2.0","method":"vendor/unknown-${index}"}`);
    }

    await until(
      () => /dropped blocked-unmapped observation .*dropped=\d+/.test(harness.stderrText()),
      "observation overflow diagnostic",
    );
  });

  it("bounds attacker-controlled tool names before sending them to the audit backend", async () => {
    let body: Record<string, unknown> | null = null;
    await observeBlockedUnmapped(
      "x".repeat(MAX_OBSERVED_TOOL_NAME_CHARS + 1024),
      ENV,
      async (_input, init) => {
        body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        return new Response(null, { status: 204 });
      },
      50,
    );

    assert.equal(String(body?.["tool_name"]).length, MAX_OBSERVED_TOOL_NAME_CHARS);
  });

  it("cancels an unused observation response body", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      cancel: () => {
        cancelled = true;
      },
    });

    await observeBlockedUnmapped(
      "vendor/unknown",
      ENV,
      async () => new Response(body, { status: 200 }),
      50,
    );

    assert.equal(cancelled, true);
  });

  it("releases a pool slot when response cancellation stalls", async () => {
    let calls = 0;
    const never = new Promise<void>(() => {});
    const observer = createBlockedUnmappedObserver(
      ENV,
      async () => {
        calls += 1;
        return new Response(
          new ReadableStream<Uint8Array>({
            cancel: () => never,
          }),
          { status: 200 },
        );
      },
      20,
    );

    observer("vendor/first");
    await settle(50);
    observer("vendor/second");
    await settle(30);

    assert.equal(calls, 2);
  });
});
