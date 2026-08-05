import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { createServerRequestTracker } from "../src/server_requests.js";

const request = (id: string): Buffer =>
  Buffer.from(JSON.stringify({ jsonrpc: "2.0", id, method: "roots/list" }) + "\n");

const requestWithProgress = (id: string, progressToken: string): Buffer =>
  Buffer.from(
    JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "roots/list",
      params: { _meta: { progressToken } },
    }) + "\n",
  );

const response = (id: string): Record<string, unknown> => ({
  jsonrpc: "2.0",
  id,
  result: {},
});

const responseLine = (id: string): Buffer =>
  Buffer.from(JSON.stringify(response(id)) + "\n");

describe("server request response correlation", () => {
  it("bounds outstanding request IDs and accepts capacity again after consumption", () => {
    const tracker = createServerRequestTracker({ maxPending: 2 });
    tracker.observer.write(request("one"));
    tracker.observer.write(request("two"));
    tracker.observer.write(request("overflow"));

    assert.equal(tracker.consumeResponse(response("one")), true);
    assert.equal(tracker.consumeResponse(response("overflow")), false);

    tracker.observer.write(request("three"));
    assert.equal(tracker.consumeResponse(response("three")), true);
  });

  it("expires unanswered request IDs without a timer or retained callback", () => {
    let now = 10;
    const tracker = createServerRequestTracker({
      maxPending: 2,
      pendingTtlMs: 5,
      now: () => now,
    });
    tracker.observer.write(request("old"));
    now = 16;

    assert.equal(tracker.consumeResponse(response("old")), false);
    tracker.observer.write(request("new"));
    assert.equal(tracker.consumeResponse(response("new")), true);
  });

  it("expires progress tokens with their unanswered server request", () => {
    let now = 10;
    const tracker = createServerRequestTracker({
      pendingTtlMs: 5,
      now: () => now,
    });
    tracker.observer.write(requestWithProgress("old", "old-progress"));
    assert.equal(tracker.canReportProgress("old-progress"), true);
    now = 16;

    assert.equal(tracker.canReportProgress("old-progress"), false);
  });

  it("drops an oversized server line as one bounded protocol unit, then recovers", () => {
    let oversizedLines = 0;
    const tracker = createServerRequestTracker({
      maxLineBytes: 256,
      onOversize: () => {
        oversizedLines += 1;
      },
    });
    const output: Buffer[] = [];
    tracker.observer.on("data", (chunk: Buffer) => output.push(chunk));
    const oversized = Buffer.alloc(257, 0x78);
    const followup = requestWithProgress("valid", "valid-progress");
    const wire = Buffer.concat([oversized, Buffer.from("\n"), followup]);

    tracker.observer.write(wire);

    assert.deepEqual(Buffer.concat(output), followup);
    assert.equal(oversizedLines, 1);
    assert.equal(tracker.canReportProgress("valid-progress"), true);
  });

  it("drops an ambiguous server request instead of creating parser-dependent correlation", () => {
    let ambiguousLines = 0;
    const tracker = createServerRequestTracker({
      onAmbiguous: () => {
        ambiguousLines += 1;
      },
    });
    const output: Buffer[] = [];
    tracker.observer.on("data", (chunk: Buffer) => output.push(chunk));
    const ambiguous = Buffer.from(
      '{"jsonrpc":"2.0","id":"first","id":"second","method":"roots/list"}\n',
    );
    const followup = request("valid");

    tracker.observer.write(Buffer.concat([ambiguous, followup]));

    assert.deepEqual(Buffer.concat(output), followup);
    assert.equal(ambiguousLines, 1);
    assert.equal(tracker.consumeResponse(response("first")), false);
    assert.equal(tracker.consumeResponse(response("second")), false);
    assert.equal(tracker.consumeResponse(response("valid")), true);
  });

  it("drops malformed UTF-8 before server-request correlation", () => {
    let ambiguousLines = 0;
    const tracker = createServerRequestTracker({
      onAmbiguous: () => {
        ambiguousLines += 1;
      },
    });
    const output: Buffer[] = [];
    tracker.observer.on("data", (chunk: Buffer) => output.push(chunk));
    const malformed = Buffer.concat([
      Buffer.from('{"jsonrpc":"2.0","id":"bad","method":"roots/l'),
      Buffer.from([0xff]),
      Buffer.from('ist"}\n'),
    ]);

    tracker.observer.write(malformed);

    assert.equal(Buffer.concat(output).length, 0);
    assert.equal(ambiguousLines, 1);
    assert.equal(tracker.consumeResponse(response("bad")), false);
  });

  it("drops non-JSON and non-message server lines", () => {
    let untrackableLines = 0;
    const tracker = createServerRequestTracker({
      onUntrackable: () => {
        untrackableLines += 1;
      },
    });
    const output: Buffer[] = [];
    tracker.observer.on("data", (chunk: Buffer) => output.push(chunk));

    tracker.observer.write(Buffer.from("not-json\n"));
    tracker.observer.write(Buffer.from('{"jsonrpc":"2.0","id":"bad"}\n'));
    tracker.observer.write(Buffer.from('{"jsonrpc":"2.0"}\n'));
    tracker.observer.write(Buffer.from('{"jsonrpc":"2.0","method":7}\n'));

    assert.equal(Buffer.concat(output).length, 0);
    assert.equal(untrackableLines, 4);
  });

  it("forwards a valid id-less server notification", () => {
    const tracker = createServerRequestTracker();
    const output: Buffer[] = [];
    tracker.observer.on("data", (chunk: Buffer) => output.push(chunk));
    const notification = Buffer.from(
      '{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}\n',
    );

    tracker.observer.write(notification);

    assert.deepEqual(Buffer.concat(output), notification);
  });

  it("drops a server response that has no pending client request", () => {
    let untrackableLines = 0;
    const tracker = createServerRequestTracker({
      onUntrackable: () => {
        untrackableLines += 1;
      },
    });
    const output: Buffer[] = [];
    tracker.observer.on("data", (chunk: Buffer) => output.push(chunk));

    tracker.observer.write(Buffer.from(JSON.stringify(response("unsolicited")) + "\n"));

    assert.equal(Buffer.concat(output).length, 0);
    assert.equal(untrackableLines, 1);
  });

  it("drops a server response while the matching client request is only reserved", () => {
    let untrackableLines = 0;
    const tracker = createServerRequestTracker({
      onUntrackable: () => {
        untrackableLines += 1;
      },
    });
    const output: Buffer[] = [];
    tracker.observer.on("data", (chunk: Buffer) => output.push(chunk));
    assert.equal(
      tracker.reserveClientRequest({ jsonrpc: "2.0", id: "checking", method: "tools/call" }),
      true,
    );

    tracker.observer.write(responseLine("checking"));

    assert.equal(Buffer.concat(output).length, 0);
    assert.equal(untrackableLines, 1);
  });

  it("forwards one matching server response and drops a duplicate", () => {
    let untrackableLines = 0;
    const tracker = createServerRequestTracker({
      onUntrackable: () => {
        untrackableLines += 1;
      },
    });
    const output: Buffer[] = [];
    tracker.observer.on("data", (chunk: Buffer) => output.push(chunk));
    assert.equal(
      tracker.reserveClientRequest({ jsonrpc: "2.0", id: "once", method: "ping" }),
      true,
    );
    assert.equal(
      tracker.markClientRequestForwarded({ jsonrpc: "2.0", id: "once", method: "ping" }),
      true,
    );
    const line = responseLine("once");

    tracker.observer.write(line);
    tracker.observer.write(line);

    assert.deepEqual(Buffer.concat(output), line);
    assert.equal(untrackableLines, 1);
  });

  it("drops an ambiguous unterminated server line when the stream closes", async () => {
    let ambiguousLines = 0;
    const tracker = createServerRequestTracker({
      onAmbiguous: () => {
        ambiguousLines += 1;
      },
    });
    const output: Buffer[] = [];
    tracker.observer.on("data", (chunk: Buffer) => output.push(chunk));
    tracker.observer.end(
      Buffer.from('{"jsonrpc":"2.0","id":"first","id":"second","method":"roots/list"}'),
    );
    await new Promise<void>((resolve) => tracker.observer.once("end", resolve));

    assert.equal(Buffer.concat(output).length, 0);
    assert.equal(ambiguousLines, 1);
    assert.equal(tracker.consumeResponse(response("first")), false);
    assert.equal(tracker.consumeResponse(response("second")), false);
  });

  it("allows cancellation only while a non-initialize client request is in flight", () => {
    const tracker = createServerRequestTracker();
    assert.equal(
      tracker.reserveClientRequest({ jsonrpc: "2.0", id: "ping", method: "ping" }),
      true,
    );
    assert.equal(
      tracker.reserveClientRequest({ jsonrpc: "2.0", id: "init", method: "initialize" }),
      true,
    );
    assert.equal(tracker.canCancelRequest("ping"), false);
    assert.equal(
      tracker.markClientRequestForwarded({ jsonrpc: "2.0", id: "ping", method: "ping" }),
      true,
    );
    assert.equal(
      tracker.markClientRequestForwarded({
        jsonrpc: "2.0",
        id: "init",
        method: "initialize",
      }),
      true,
    );

    assert.equal(tracker.canCancelRequest("ping"), true);
    assert.equal(tracker.canCancelRequest("init"), false);
    tracker.observer.write(Buffer.from(JSON.stringify(response("ping")) + "\n"));
    assert.equal(tracker.canCancelRequest("ping"), false);
  });

  it("forwards a server response whose client request outlived the pending TTL", () => {
    // A tools/call can legitimately run for longer than the TTL (a build, a
    // test suite). Evicting the client request would make its eventual answer
    // untrackable and drop it, leaving the client waiting forever with no
    // error — an availability failure, not a fail-closed one.
    let now = 10;
    let untrackable = 0;
    const tracker = createServerRequestTracker({
      pendingTtlMs: 5,
      now: () => now,
      onUntrackable: () => {
        untrackable += 1;
      },
    });
    const output: Buffer[] = [];
    tracker.observer.on("data", (chunk: Buffer) => output.push(chunk));
    assert.equal(
      tracker.reserveClientRequest({ jsonrpc: "2.0", id: 7, method: "tools/call" }),
      true,
    );
    assert.equal(
      tracker.markClientRequestForwarded({
        jsonrpc: "2.0",
        id: 7,
        method: "tools/call",
      }),
      true,
    );
    now = 10_000;
    const answer = Buffer.from(
      JSON.stringify({ jsonrpc: "2.0", id: 7, result: {} }) + "\n",
    );

    tracker.observer.write(answer);

    assert.deepEqual(Buffer.concat(output), answer);
    assert.equal(untrackable, 0);
  });

  it("keeps a long-running client request cancellable past the pending TTL", () => {
    let now = 10;
    const tracker = createServerRequestTracker({ pendingTtlMs: 5, now: () => now });
    assert.equal(
      tracker.reserveClientRequest({ jsonrpc: "2.0", id: "slow", method: "tools/call" }),
      true,
    );
    assert.equal(
      tracker.markClientRequestForwarded({
        jsonrpc: "2.0",
        id: "slow",
        method: "tools/call",
      }),
      true,
    );
    now = 10_000;

    assert.equal(tracker.canCancelRequest("slow"), true);
  });

  it("rejects a duplicate outstanding client request ID without changing its owner", () => {
    const tracker = createServerRequestTracker();
    assert.equal(
      tracker.reserveClientRequest({ jsonrpc: "2.0", id: 7, method: "ping" }),
      true,
    );
    assert.equal(
      tracker.markClientRequestForwarded({ jsonrpc: "2.0", id: 7, method: "ping" }),
      true,
    );
    assert.equal(
      tracker.reserveClientRequest({ jsonrpc: "2.0", id: 7, method: "initialize" }),
      false,
    );
    assert.equal(tracker.canCancelRequest(7), true);
  });

  it("can release a reserved client request that was denied before forwarding", () => {
    const tracker = createServerRequestTracker();
    const message = { jsonrpc: "2.0", id: 8, method: "ping" };
    assert.equal(tracker.reserveClientRequest(message), true);
    tracker.releaseClientRequest(message);
    assert.equal(tracker.reserveClientRequest(message), true);
  });

  it("rejects a progress token reused by concurrent client requests", () => {
    const tracker = createServerRequestTracker();
    const first = {
      jsonrpc: "2.0",
      id: "first",
      method: "resources/read",
      params: { _meta: { progressToken: "shared-progress" } },
    };
    const second = {
      jsonrpc: "2.0",
      id: "second",
      method: "resources/read",
      params: { _meta: { progressToken: "shared-progress" } },
    };

    assert.equal(tracker.reserveClientRequest(first), true);
    assert.equal(tracker.reserveClientRequest(second), false);
    tracker.releaseClientRequest(first);
    assert.equal(tracker.reserveClientRequest(second), true);
  });

  it("bounds individual and total correlation-key bytes", () => {
    let untrackable = 0;
    const tracker = createServerRequestTracker({
      maxPending: 10,
      maxKeyBytes: 16,
      maxPendingBytes: 12,
      onUntrackable: () => {
        untrackable += 1;
      },
    });
    const output: Buffer[] = [];
    tracker.observer.on("data", (chunk: Buffer) => output.push(chunk));
    const first = request("a");
    const second = request("b");

    tracker.observer.write(request("x".repeat(32)));
    tracker.observer.write(first);
    tracker.observer.write(second);

    assert.deepEqual(Buffer.concat(output), first);
    assert.equal(untrackable, 2);
    assert.equal(tracker.consumeResponse(response("a")), true);

    tracker.observer.write(second);
    assert.deepEqual(Buffer.concat(output), Buffer.concat([first, second]));
    assert.equal(tracker.consumeResponse(response("b")), true);
  });

  it("applies the same byte budget to client request correlation", () => {
    const tracker = createServerRequestTracker({
      maxPending: 10,
      maxKeyBytes: 16,
      maxPendingBytes: 12,
    });
    assert.equal(
      tracker.reserveClientRequest({ jsonrpc: "2.0", id: "x".repeat(32), method: "ping" }),
      false,
    );
    assert.equal(
      tracker.reserveClientRequest({ jsonrpc: "2.0", id: "a", method: "ping" }),
      true,
    );
    assert.equal(
      tracker.reserveClientRequest({ jsonrpc: "2.0", id: "b", method: "ping" }),
      false,
    );
    assert.equal(
      tracker.markClientRequestForwarded({ jsonrpc: "2.0", id: "a", method: "ping" }),
      true,
    );
    tracker.observer.write(Buffer.from(JSON.stringify(response("a")) + "\n"));
    assert.equal(
      tracker.reserveClientRequest({ jsonrpc: "2.0", id: "b", method: "ping" }),
      true,
    );
  });

  it("drops a server request whose progress token exceeds the key budget", () => {
    let untrackable = 0;
    const tracker = createServerRequestTracker({
      maxKeyBytes: 16,
      onUntrackable: () => {
        untrackable += 1;
      },
    });
    const output: Buffer[] = [];
    tracker.observer.on("data", (chunk: Buffer) => output.push(chunk));
    const longToken = "x".repeat(32);

    tracker.observer.write(requestWithProgress("a", longToken));

    assert.equal(Buffer.concat(output).length, 0);
    assert.equal(untrackable, 1);
    assert.equal(tracker.canReportProgress(longToken), false);
    assert.equal(tracker.consumeResponse(response("a")), false);
  });

  it("drops a server request whose progress token already belongs to another request", () => {
    let untrackable = 0;
    const tracker = createServerRequestTracker({
      onUntrackable: () => {
        untrackable += 1;
      },
    });
    const output: Buffer[] = [];
    tracker.observer.on("data", (chunk: Buffer) => output.push(chunk));
    const first = requestWithProgress("first", "shared");
    const second = requestWithProgress("second", "shared");

    tracker.observer.write(first);
    tracker.observer.write(second);

    assert.deepEqual(Buffer.concat(output), first);
    assert.equal(untrackable, 1);
    assert.equal(tracker.canReportProgress("shared"), true);
    assert.equal(tracker.consumeResponse(response("second")), false);
    assert.equal(tracker.consumeResponse(response("first")), true);

    tracker.observer.write(second);
    assert.deepEqual(Buffer.concat(output), Buffer.concat([first, second]));
    assert.equal(tracker.consumeResponse(response("second")), true);
  });
});
