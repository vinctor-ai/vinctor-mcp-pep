import { describe, it, afterEach } from "node:test";
import { strict as assert } from "node:assert";
import { startHarness, until, settle, type Harness } from "./helpers.js";
import { DENY_MESSAGE } from "../src/enforce.js";

// Task 1: transparent stdio proxy. The mock MCP server (spawned by the proxy
// as a real child process) echoes the raw bytes it received in each response,
// so byte-faithfulness can be asserted end to end.

let h: Harness;
afterEach(async () => {
  if (h) await h.stop();
});

type EchoResponse = {
  jsonrpc: string;
  id: string | number;
  result: { echoMethod: string; echoRaw: string };
};

describe("transparent stdio proxy (task 1)", () => {
  it("initialize round-trips unmodified through the proxy", async () => {
    h = startHarness({});
    // Deliberately quirky whitespace/key-order: pass-through must be byte-faithful.
    const raw = '{"jsonrpc": "2.0",  "id": 1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"roots":{"listChanged":true},"sampling":{},"elicitation":{},"experimental":{"vendor":{}},"vendor":{"enabled":true}},"clientInfo":{"name":"t","title":"Test Client","version":"1"}}}';
    h.send(raw);
    await until(() => h.clientLines.length >= 1, "initialize response");
    const res = JSON.parse(h.clientLines[0]!) as EchoResponse;
    assert.equal(res.id, 1);
    assert.equal(res.result.echoMethod, "initialize");
    assert.equal(res.result.echoRaw, raw); // server received the ORIGINAL bytes
  });

  it("tools/list round-trips and the server response reaches the client verbatim", async () => {
    h = startHarness({});
    const raw = '{"jsonrpc":"2.0","id":"list-1","method":"tools/list"}';
    h.send(raw);
    await until(() => h.clientLines.length >= 1, "tools/list response");
    // The mock writes exactly one JSON line; the client must see that line as-is.
    const expected = JSON.stringify({
      jsonrpc: "2.0",
      id: "list-1",
      result: { echoMethod: "tools/list", echoRaw: raw },
    });
    assert.equal(h.clientLines[0], expected);
  });

  it("notifications (no id) pass through to the server without a response", async () => {
    h = startHarness({});
    const note = '{"jsonrpc":"2.0","method":"notifications/initialized"}';
    h.send(note);
    h.send('{"jsonrpc":"2.0","id":2,"method":"ping"}');
    await until(() => h.clientLines.length >= 1, "ping response");
    assert.equal(h.clientLines.length, 1); // notification produced no response
    assert.deepEqual(h.serverLog(), [note, '{"jsonrpc":"2.0","id":2,"method":"ping"}']);
  });

  it("chunk boundaries do not corrupt framing (line split across writes)", async () => {
    h = startHarness({});
    const raw = '{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}';
    // Write in three fragments; only the final \n completes the message.
    const third = Math.floor(raw.length / 3);
    h.sendRaw(raw.slice(0, third));
    h.sendRaw(raw.slice(third, 2 * third));
    h.sendRaw(raw.slice(2 * third) + "\n");
    await until(() => h.clientLines.length >= 1, "fragmented initialize response");
    const res = JSON.parse(h.clientLines[0]!) as EchoResponse;
    assert.equal(res.result.echoRaw, raw);
  });

  it("server stderr passes through to proxy stderr", async () => {
    h = startHarness({});
    await until(() => h.stderrText().includes("mock-mcp-server started"), "server stderr");
  });

  it("proxy resolves with the server's exit code when client input ends", async () => {
    h = startHarness({});
    h.send('{"jsonrpc":"2.0","id":4,"method":"ping"}');
    await until(() => h.clientLines.length >= 1, "ping response");
    h.endInput();
    const code = await h.proxy.done;
    assert.equal(code, 0);
  });
});

describe("fail-closed JSON-RPC method dispatch (PKA-100)", () => {
  // No VINCTOR_* env: every enforce check fails closed, so any method that is
  // ENFORCED (rather than passed through) must come back as the deny error.
  const EXPECTED_DENY = (id: number | string | null): string =>
    JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32000, message: DENY_MESSAGE } });
  const ENFORCE_ENV = {
    VINCTOR_ENDPOINT: "https://vinctor.example",
    VINCTOR_PEP_KEY: "pep_test_key",
    VINCTOR_GRANT_REF: "grt_test_ref",
    VINCTOR_WORKSPACE_ID: "ws_test",
    VINCTOR_AGENT_ID: "agent_test",
  };
  const permitFetch = (calls: { count: number }): typeof fetch =>
    (async (): Promise<Response> => {
      calls.count += 1;
      return new Response(
        JSON.stringify({ decision: "permit", audit_event_id: `evt_${calls.count}` }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }) as typeof fetch;

  it("resources/read is enforced, never silently forwarded", async () => {
    h = startHarness({});
    h.send('{"jsonrpc":"2.0","id":40,"method":"resources/read","params":{"uri":"file:///workspace/notes.txt"}}');
    await until(() => h.clientLines.length >= 1, "resources/read deny");
    assert.equal(h.clientLines[0], EXPECTED_DENY(40));
    await settle();
    assert.deepEqual(h.serverLog(), []);
  });

  it("prompts/get is enforced, never silently forwarded", async () => {
    h = startHarness({});
    h.send('{"jsonrpc":"2.0","id":41,"method":"prompts/get","params":{"name":"greet"}}');
    await until(() => h.clientLines.length >= 1, "prompts/get deny");
    assert.equal(h.clientLines[0], EXPECTED_DENY(41));
    await settle();
    assert.deepEqual(h.serverLog(), []);
  });

  it("an unknown method with an id is denied, not forwarded", async () => {
    h = startHarness({});
    h.send('{"jsonrpc":"2.0","id":42,"method":"debug/eval","params":{"code":"process.env"}}');
    await until(() => h.clientLines.length >= 1, "unknown-method deny");
    assert.equal(h.clientLines[0], EXPECTED_DENY(42));
    await settle();
    assert.deepEqual(h.serverLog(), []);
  });

  it("an unknown method stays denied when unmapped tools are configured to allow", async () => {
    h = startHarness({}, { unmappedVerdict: "allow" });
    h.send('{"jsonrpc":"2.0","id":47,"method":"debug/eval","params":{"code":"process.env"}}');
    await until(() => h.clientLines.length >= 1, "unknown-method deny under tool opt-out");
    assert.equal(h.clientLines[0], EXPECTED_DENY(47));
    await settle();
    assert.deepEqual(h.serverLog(), []);
  });

  it("an unknown notification (no id) is dropped without a response", async () => {
    h = startHarness({});
    h.send('{"jsonrpc":"2.0","method":"debug/exfil","params":{"x":1}}');
    h.send('{"jsonrpc":"2.0","id":43,"method":"ping"}');
    await until(() => h.clientLines.length >= 1, "ping after dropped notification");
    // JSON-RPC forbids responding to a notification: only the ping answered.
    assert.equal(h.clientLines.length, 1);
    assert.deepEqual(h.serverLog(), ['{"jsonrpc":"2.0","id":43,"method":"ping"}']);
  });

  it("an unknown notification stays dropped when unmapped tools are configured to allow", async () => {
    h = startHarness({}, { unmappedVerdict: "allow" });
    h.send('{"jsonrpc":"2.0","method":"debug/exfil","params":{"x":1}}');
    h.send('{"jsonrpc":"2.0","id":48,"method":"ping"}');
    await until(() => h.clientLines.length >= 1, "ping after dropped notification under tool opt-out");
    assert.deepEqual(h.serverLog(), ['{"jsonrpc":"2.0","id":48,"method":"ping"}']);
    assert.match(h.stderrText(), /dropped unmapped notification/);
  });

  it("malformed tools/call never uses the unmapped-tool allow escape hatch", async () => {
    h = startHarness({}, { unmappedVerdict: "allow" });
    const malformedRequests = [
      '{"jsonrpc":"2.0","id":60,"method":"tools/call"}',
      '{"jsonrpc":"2.0","id":61,"method":"tools/call","params":null}',
      '{"jsonrpc":"2.0","id":62,"method":"tools/call","params":[]}',
      '{"jsonrpc":"2.0","id":63,"method":"tools/call","params":{}}',
      '{"jsonrpc":"2.0","id":64,"method":"tools/call","params":{"name":7}}',
      '{"jsonrpc":"2.0","id":65,"method":"tools/call","params":{"name":""}}',
      '{"jsonrpc":"2.0","id":66,"method":"tools/call","params":{"name":"vendor/tool","arguments":null}}',
      '{"jsonrpc":"2.0","id":67,"method":"tools/call","params":{"name":"vendor/tool","arguments":[]}}',
      '{"jsonrpc":"2.0","id":68,"method":"tools/call","params":{"name":"vendor/tool","arguments":"x"}}',
    ];
    for (const raw of malformedRequests) h.send(raw);
    h.send('{"jsonrpc":"2.0","method":"tools/call","params":{"name":"vendor/tool","arguments":{}}}');
    const ping = '{"jsonrpc":"2.0","id":69,"method":"ping"}';
    h.send(ping);

    await until(() => h.clientLines.length >= malformedRequests.length + 1, "malformed tools/call denials");
    assert.deepEqual(
      h.clientLines.slice(0, malformedRequests.length),
      malformedRequests.map((_, index) => EXPECTED_DENY(60 + index)),
    );
    assert.deepEqual(h.serverLog(), [ping]);
    assert.match(h.stderrText(), /dropped malformed client message/);
  });

  it("malformed JSON-RPC envelopes and lifecycle shapes fail closed before dispatch", async () => {
    h = startHarness({}, { unmappedVerdict: "allow" });
    const malformedRequests = [
      '{"id":70,"method":"ping"}',
      '{"jsonrpc":"1.0","id":71,"method":"ping"}',
      '{"jsonrpc":"2.0","id":72.5,"method":"ping"}',
      '{"jsonrpc":"2.0","id":9007199254740992,"method":"ping"}',
      '{"jsonrpc":"2.0","id":null,"method":"ping"}',
      '{"jsonrpc":"2.0","id":73,"method":"ping","params":null}',
      '{"jsonrpc":"2.0","id":74,"method":"ping","params":[]}',
      '{"jsonrpc":"2.0","id":75,"method":"ping","params":"x"}',
      '{"jsonrpc":"2.0","id":76,"method":"initialize","params":{}}',
      '{"jsonrpc":"2.0","id":77,"method":"logging/setLevel","params":{}}',
      '{"jsonrpc":"2.0","id":78,"method":"notifications/initialized"}',
    ];
    for (const raw of malformedRequests) h.send(raw);
    h.send('{"jsonrpc":"2.0","method":"ping"}');
    h.send('{"jsonrpc":"2.0","method":"notifications/cancelled"}');
    h.send('{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"p"}}');
    const ping = '{"jsonrpc":"2.0","id":79,"method":"ping"}';
    h.send(ping);

    await until(() => h.clientLines.length >= malformedRequests.length + 1, "malformed lifecycle denials");
    assert.deepEqual(
      h.clientLines.slice(0, malformedRequests.length),
      [
        EXPECTED_DENY(70),
        EXPECTED_DENY(71),
        EXPECTED_DENY(null),
        EXPECTED_DENY(null),
        EXPECTED_DENY(null),
        EXPECTED_DENY(73),
        EXPECTED_DENY(74),
        EXPECTED_DENY(75),
        EXPECTED_DENY(76),
        EXPECTED_DENY(77),
        EXPECTED_DENY(78),
      ],
    );
    assert.deepEqual(h.serverLog(), [ping]);
    assert.match(h.stderrText(), /dropped malformed client message/);
  });

  it("nested lifecycle and capability fields use the same strict protocol types", async () => {
    h = startHarness({}, { unmappedVerdict: "allow" });
    const malformedRequests = [
      '{"jsonrpc":"2.0","id":100,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"roots":7},"clientInfo":{"name":"t","version":"1"}}}',
      '{"jsonrpc":"2.0","id":101,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"roots":{"listChanged":"yes"}},"clientInfo":{"name":"t","version":"1"}}}',
      '{"jsonrpc":"2.0","id":102,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"experimental":{"vendor":null}},"clientInfo":{"name":"t","version":"1"}}}',
      '{"jsonrpc":"2.0","id":103,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"sampling":[]},"clientInfo":{"name":"t","version":"1"}}}',
      '{"jsonrpc":"2.0","id":104,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"elicitation":"yes"},"clientInfo":{"name":"t","version":"1"}}}',
      '{"jsonrpc":"2.0","id":105,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1","title":7}}}',
      '{"jsonrpc":"2.0","id":106,"method":"ping","params":{"_meta":"bad"}}',
      '{"jsonrpc":"2.0","id":107,"method":"tools/call","params":{"name":"vendor/tool","_meta":null}}',
      '{"jsonrpc":"2.0","id":108,"method":"ping","params":{"_meta":{"progressToken":{}}}}',
    ];
    for (const raw of malformedRequests) h.send(raw);
    h.send('{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1.5}}');
    h.send('{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9007199254740992}}');
    h.send('{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":false,"progress":1}}');
    h.send('{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":{},"progress":1}}');
    const ping = '{"jsonrpc":"2.0","id":109,"method":"ping"}';
    h.send(ping);

    await until(() => h.clientLines.length >= malformedRequests.length + 1, "nested protocol denials");
    assert.deepEqual(
      h.clientLines.slice(0, malformedRequests.length),
      malformedRequests.map((_, index) => EXPECTED_DENY(100 + index)),
    );
    assert.deepEqual(h.serverLog(), [ping]);
  });

  it("malformed enforced-method params are rejected before authorization", async () => {
    const calls = { count: 0 };
    h = startHarness(ENFORCE_ENV, { fetchFn: permitFetch(calls) });
    const malformedRequests = [
      '{"jsonrpc":"2.0","id":90,"method":"resources/list","params":{"cursor":7}}',
      '{"jsonrpc":"2.0","id":91,"method":"resources/templates/list","params":{"cursor":false}}',
      '{"jsonrpc":"2.0","id":92,"method":"prompts/list","params":{"cursor":[]}}',
      '{"jsonrpc":"2.0","id":93,"method":"prompts/get","params":{"name":"greet","arguments":[]}}',
      '{"jsonrpc":"2.0","id":94,"method":"prompts/get","params":{"name":"greet","arguments":{"topic":7}}}',
      '{"jsonrpc":"2.0","id":95,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"greet"}}}',
      '{"jsonrpc":"2.0","id":96,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"greet"},"argument":null}}',
      '{"jsonrpc":"2.0","id":97,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"greet"},"argument":{"name":7,"value":"v"}}}',
      '{"jsonrpc":"2.0","id":98,"method":"completion/complete","params":{"ref":{"type":"ref/resource","uri":"file:///w/data.csv"},"argument":{"name":"x"}}}',
      '{"jsonrpc":"2.0","id":99,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"greet"},"argument":{"name":"x","value":"v"},"context":[]}}',
      '{"jsonrpc":"2.0","id":100,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"greet"},"argument":{"name":"x","value":"v"},"context":{"arguments":{"topic":7}}}}',
    ];
    for (const raw of malformedRequests) h.send(raw);
    const ping = '{"jsonrpc":"2.0","id":109,"method":"ping"}';
    h.send(ping);

    await until(() => h.clientLines.length >= malformedRequests.length + 1, "malformed enforced-method denials");
    assert.deepEqual(
      h.clientLines.slice(0, malformedRequests.length),
      malformedRequests.map((_, index) => EXPECTED_DENY(90 + index)),
    );
    assert.equal(calls.count, 0);
    assert.deepEqual(h.serverLog(), [ping]);
  });

  it("request and notification envelopes reject response-only members", async () => {
    h = startHarness({}, { unmappedVerdict: "allow" });
    h.send('{"jsonrpc":"2.0","id":81,"method":"ping","result":{}}');
    h.send(
      '{"jsonrpc":"2.0","id":82,"method":"tools/call","params":{"name":"vendor/tool","arguments":{}},"error":{"code":1,"message":"x"}}',
    );
    h.send('{"jsonrpc":"2.0","method":"notifications/initialized","result":{}}');
    const ping = '{"jsonrpc":"2.0","id":83,"method":"ping"}';
    h.send(ping);

    await until(() => h.clientLines.length >= 3, "mixed request/response envelope denials");
    const pingResponse = JSON.stringify({
      jsonrpc: "2.0",
      id: 83,
      result: { echoMethod: "ping", echoRaw: ping },
    });
    assert.deepEqual(h.clientLines, [EXPECTED_DENY(81), EXPECTED_DENY(82), pingResponse]);
    assert.deepEqual(h.serverLog(), [ping]);
    assert.match(h.stderrText(), /dropped malformed client message/);
  });

  it("duplicate JSON object keys are rejected before any parser-dependent dispatch", async () => {
    h = startHarness({}, { unmappedVerdict: "allow" });
    h.send(
      '{"jsonrpc":"2.0","id":84,"method":"tools/call","method":"ping","params":{"name":"vendor/tool","arguments":{}}}',
    );
    h.send(
      '{"jsonrpc":"2.0","id":85,"method":"ping","params":{"_meta":{},"_meta":{"vendor":true}}}',
    );
    const ping = '{"jsonrpc":"2.0","id":86,"method":"ping"}';
    h.send(ping);

    await until(() => h.clientLines.length >= 3, "duplicate-key denials and live response");
    assert.deepEqual(h.clientLines.slice(0, 2), [EXPECTED_DENY(null), EXPECTED_DENY(null)]);
    assert.deepEqual(h.serverLog(), [ping]);
  });

  it("only well-formed client responses reach the server", async () => {
    h = startHarness({ MOCK_SERVER_REQUEST_IDS: '["srv-2","srv-3"]' });
    await until(() => h.clientLines.length >= 2, "server-initiated requests");
    for (const raw of [
      '{"jsonrpc":"2.0","id":"bad-1","error":null}',
      '{"jsonrpc":"2.0","id":"bad-2","error":{}}',
      '{"jsonrpc":"2.0","id":"bad-3","error":{"code":"x","message":"bad"}}',
      '{"jsonrpc":"2.0","id":"bad-4","error":{"code":1}}',
      '{"jsonrpc":"2.0","id":"bad-5","error":{"code":1.5,"message":"bad"}}',
      '{"jsonrpc":"2.0","id":"bad-6","result":{},"error":{"code":1,"message":"bad"}}',
      '{"jsonrpc":"2.0","id":"bad-7","result":null}',
      '{"jsonrpc":"2.0","id":"bad-8","result":[]}',
      '{"jsonrpc":"2.0","id":"bad-9","result":"ok"}',
      '{"jsonrpc":"2.0","id":"unsolicited","result":{}}',
    ]) {
      h.send(raw);
    }
    const validResult = '{"jsonrpc":"2.0","id":"srv-2","result":{"roots":[]}}';
    const validError =
      '{"jsonrpc":"2.0","id":"srv-3","error":{"code":-32601,"message":"not found"}}';
    h.send(validResult);
    h.send(validResult);
    h.send(validError);

    await until(() => h.serverLog().length >= 2, "valid client responses forwarded");
    await settle();
    assert.deepEqual(h.serverLog(), [validResult, validError]);
    assert.match(h.stderrText(), /dropped malformed client message/);
  });

  it("a structurally valid mapper-unknown tool still follows the explicit allow opt-out", async () => {
    h = startHarness({}, { unmappedVerdict: "allow" });
    const raw =
      '{"jsonrpc":"2.0","id":80,"method":"tools/call","params":{"name":"vendor/tool","arguments":{"x":1}}}';
    h.send(raw);
    await until(() => h.clientLines.length >= 1, "valid unmapped tool response");
    const res = JSON.parse(h.clientLines[0]!) as EchoResponse;
    assert.equal(res.id, 80);
    assert.equal(res.result.echoRaw, raw);
    assert.deepEqual(h.serverLog(), [raw]);
  });

  it("client response messages (id + result, no method) pass through", async () => {
    h = startHarness({ MOCK_SERVER_REQUEST_IDS: '["srv-1"]' });
    // The client's reply to a server-initiated request (sampling/roots) must
    // still reach the server or the protocol deadlocks.
    await until(() => h.clientLines.length >= 1, "server-initiated request");
    const reply = '{"jsonrpc":"2.0","id":"srv-1","result":{"roots":[]}}';
    h.send(reply);
    await until(() => h.serverLog().length >= 1, "response forwarded to server");
    assert.deepEqual(h.serverLog(), [reply]);
  });

  it("cancellation forwards only for an in-flight non-initialize client request", async () => {
    h = startHarness({ MOCK_SERVER_HOLD_IDS: "[200,201]" });
    const initialize =
      '{"jsonrpc":"2.0","id":200,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}';
    const pendingPing = '{"jsonrpc":"2.0","id":201,"method":"ping"}';
    h.send(initialize);
    h.send(pendingPing);
    await until(() => h.serverLog().length >= 2, "held client requests");

    h.send('{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":200}}');
    const validCancellation =
      '{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":201}}';
    h.send(validCancellation);
    h.send('{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":999}}');
    const livePing = '{"jsonrpc":"2.0","id":202,"method":"ping"}';
    h.send(livePing);

    await until(() => h.clientLines.length >= 1, "ping after cancellation checks");
    assert.deepEqual(h.serverLog(), [initialize, pendingPing, validCancellation, livePing]);
    assert.match(h.stderrText(), /dropped malformed client message/);
  });

  it("a duplicate in-flight request ID is denied without replacing its cancellation owner", async () => {
    h = startHarness({ MOCK_SERVER_HOLD_IDS: "[301]" });
    const pendingPing = '{"jsonrpc":"2.0","id":301,"method":"ping"}';
    h.send(pendingPing);
    await until(() => h.serverLog().length >= 1, "first held request");
    h.send(
      '{"jsonrpc":"2.0","id":301,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}',
    );
    const cancellation =
      '{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":301}}';
    h.send(cancellation);
    const livePing = '{"jsonrpc":"2.0","id":302,"method":"ping"}';
    h.send(livePing);

    await until(() => h.clientLines.length >= 2, "duplicate denial and live response");
    assert.deepEqual(h.serverLog(), [pendingPing, cancellation, livePing]);
    assert.deepEqual(h.clientLines.slice(0, 1), [EXPECTED_DENY(301)]);
  });

  it("rejects a duplicate in-flight request ID before recording another permit", async () => {
    const calls = { count: 0 };
    h = startHarness(
      { ...ENFORCE_ENV, MOCK_SERVER_HOLD_IDS: "[303]" },
      { fetchFn: permitFetch(calls) },
    );
    const first =
      '{"jsonrpc":"2.0","id":303,"method":"resources/read","params":{"uri":"file:///workspace/first.txt"}}';
    h.send(first);
    await until(() => h.serverLog().length === 1, "first held enforced request");

    h.send(
      '{"jsonrpc":"2.0","id":303,"method":"resources/read","params":{"uri":"file:///workspace/second.txt"}}',
    );
    await until(() => h.clientLines.length >= 1, "duplicate enforced request denial");

    assert.equal(calls.count, 1);
    assert.deepEqual(h.serverLog(), [first]);
    assert.equal(h.clientLines[0], EXPECTED_DENY(303));
  });

  it("drops a matching child response until the client request has passed enforcement", async () => {
    let calls = 0;
    let resolvePermit!: (response: Response) => void;
    const pendingPermit = new Promise<Response>((resolve) => {
      resolvePermit = resolve;
    });
    const delayedPermitFetch = (async (): Promise<Response> => {
      calls += 1;
      return pendingPermit;
    }) as typeof fetch;
    const forgedResponse = {
      jsonrpc: "2.0",
      id: 304,
      result: { forgedBeforePermit: true },
    };
    h = startHarness(
      {
        ...ENFORCE_ENV,
        MOCK_SERVER_SIGNAL_MESSAGES: JSON.stringify([forgedResponse]),
      },
      { fetchFn: delayedPermitFetch },
    );
    const request =
      '{"jsonrpc":"2.0","id":304,"method":"resources/read","params":{"uri":"file:///workspace/report.txt"}}';

    h.send(request);
    await until(() => calls === 1, "enforcement request started");
    await until(() => h.stderrText().includes("mock-mcp-server started"), "mock server ready");
    h.emitServerMessages();
    await until(
      () => h.stderrText().includes("dropped untrackable server request"),
      "pre-permit response dropped",
    );
    assert.deepEqual(h.clientLines, []);
    assert.deepEqual(h.serverLog(), []);

    resolvePermit(
      new Response(JSON.stringify({ decision: "permit", audit_event_id: "evt_304" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    await until(() => h.clientLines.length === 1, "authorized server response");

    const response = JSON.parse(h.clientLines[0]!) as EchoResponse;
    assert.equal(response.id, 304);
    assert.equal(response.result.echoMethod, "resources/read");
    assert.deepEqual(h.serverLog(), [request]);
  });

  it("releases correlation when an authorized request cannot be written to the child", async () => {
    const calls = { count: 0 };
    const childResponse = {
      jsonrpc: "2.0",
      id: 305,
      result: { responseToUnwrittenRequest: true },
    };
    h = startHarness(
      {
        ...ENFORCE_ENV,
        MOCK_SERVER_KEEP_ALIVE_AFTER_STDIN: "1",
        MOCK_SERVER_SIGNAL_MESSAGES: JSON.stringify([childResponse]),
      },
      { fetchFn: permitFetch(calls) },
    );
    await until(() => h.stderrText().includes("mock-mcp-server started"), "mock server ready");
    h.closeChildInput();
    await until(() => h.proxy.child.stdin.destroyed, "child stdin closed");

    h.send(
      '{"jsonrpc":"2.0","id":305,"method":"resources/read","params":{"uri":"file:///workspace/unwritten.txt"}}',
    );
    await until(() => calls.count === 1, "authorization completed");
    await settle();
    h.emitServerMessages();
    await until(
      () =>
        h.clientLines.length > 0 ||
        h.stderrText().includes("dropped untrackable server request"),
      "response to unwritten request handled",
    );

    assert.deepEqual(h.clientLines, []);
    assert.deepEqual(h.serverLog(), []);
  });

  it("progress notifications require a token from an active server request", async () => {
    h = startHarness({
      MOCK_SERVER_REQUESTS: JSON.stringify([
        {
          jsonrpc: "2.0",
          id: "progress-request",
          method: "roots/list",
          params: { _meta: { progressToken: 1.5 } },
        },
      ]),
    });
    await until(() => h.clientLines.length >= 1, "server request with progress token");
    h.send(
      '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"unsolicited","progress":1}}',
    );
    const validProgress =
      '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1.5,"progress":1,"total":2}}';
    h.send(validProgress);
    const response = '{"jsonrpc":"2.0","id":"progress-request","result":{"roots":[]}}';
    h.send(response);
    h.send(
      '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1.5,"progress":2}}',
    );

    await until(() => h.serverLog().length >= 2, "correlated progress and response");
    await settle();
    assert.deepEqual(h.serverLog(), [validProgress, response]);
    assert.match(h.stderrText(), /dropped malformed client message/);
  });

  it("logging/setLevel and enumerated non-progress notifications still pass through", async () => {
    h = startHarness({});
    h.send(
      '{"jsonrpc":"2.0","method":"notifications/roots/list_changed","params":{"_meta":{"progressToken":{"vendor":"opaque"}}}}',
    );
    h.send('{"jsonrpc":"2.0","id":44,"method":"logging/setLevel","params":{"level":"info"}}');
    await until(() => h.clientLines.length >= 1, "logging/setLevel response");
    assert.equal(h.serverLog().length, 2);
  });

  it("ANY JSON-RPC batch is denied (MCP stdio has no batches; one could smuggle any request)", async () => {
    h = startHarness({});
    h.send('[{"jsonrpc":"2.0","id":45,"method":"ping"}]');
    await until(() => h.clientLines.length >= 1, "batch deny");
    assert.equal(h.clientLines[0], EXPECTED_DENY(null));
    await settle();
    assert.deepEqual(h.serverLog(), []);
  });

  it("an object that is neither a request nor a response is dropped fail-closed", async () => {
    h = startHarness({});
    h.send('{"jsonrpc":"2.0","payload":"junk"}');
    h.send('{"jsonrpc":"2.0","id":46,"method":"ping"}');
    await until(() => h.clientLines.length >= 1, "ping after dropped junk");
    assert.deepEqual(h.serverLog(), ['{"jsonrpc":"2.0","id":46,"method":"ping"}']);
  });
});

describe("non-JSON client input (fail-closed drop)", () => {
  it("a line our parser rejects is dropped, never forwarded (lenient-parser smuggling)", async () => {
    h = startHarness({});
    // JSON5-ish single quotes: OUR parser rejects it, but a lenient downstream
    // parser could read a tools/call out of it — so it must never reach the server.
    h.send("{'jsonrpc':'2.0','id':9,'method':'tools/call','params':{'name':'write_file','arguments':{'path':'x'}}}");
    h.send('{"jsonrpc":"2.0","id":10,"method":"ping"}');
    await until(() => h.clientLines.length >= 1, "ping response");
    assert.deepEqual(h.serverLog(), ['{"jsonrpc":"2.0","id":10,"method":"ping"}']);
  });

  it("a line containing malformed UTF-8 is dropped before JSON parsing", async () => {
    h = startHarness({});
    const invalid = Buffer.concat([
      Buffer.from('{"jsonrpc":"2.0","id":49,"method":"ping","tag":"'),
      Buffer.from([0xff]),
      Buffer.from('"}\n'),
    ]);
    h.sendRaw(invalid);
    const ping = '{"jsonrpc":"2.0","id":50,"method":"ping"}';
    h.send(ping);

    await until(() => h.clientLines.length >= 1, "ping after malformed UTF-8");
    assert.deepEqual(h.serverLog(), [ping]);
  });

  it("an oversized unterminated line is dropped and drained before the next message", async () => {
    h = startHarness({}, { maxLineBytes: 256 });
    h.sendRaw("x".repeat(257));
    const ping = '{"jsonrpc":"2.0","id":47,"method":"ping"}';
    h.sendRaw(`\n${ping}\n`);

    await until(() => h.clientLines.length >= 1, "ping after oversized line");
    assert.deepEqual(h.serverLog(), [ping]);
    assert.match(h.stderrText(), /dropped oversized client line/);
  });

  it("an oversized server message is dropped whole under the same protocol ceiling", async () => {
    h = startHarness(
      {
        MOCK_SERVER_REQUESTS: JSON.stringify([
          {
            jsonrpc: "2.0",
            id: "oversized-server-request",
            method: "roots/list",
            params: { payload: "x".repeat(512) },
          },
        ]),
      },
      { maxLineBytes: 256 },
    );
    await until(() => /dropped oversized server line/.test(h.stderrText()), "oversized server drop");
    h.send('{"jsonrpc":"2.0","id":"oversized-server-request","result":{"roots":[]}}');
    const ping = '{"jsonrpc":"2.0","id":48,"method":"ping"}';
    h.send(ping);

    await until(() => h.clientLines.length >= 1, "ping after oversized server line");
    assert.deepEqual(h.serverLog(), [ping]);
    assert.equal((JSON.parse(h.clientLines[0]!) as EchoResponse).id, 48);
  });
});

describe("client-to-server backpressure", () => {
  it(
    "bounds a stalled child stdin and forwards every message after it drains",
    { skip: process.platform === "win32" },
    async () => {
      h = startHarness({ MOCK_SERVER_STALL_STDIN: "1" }, { maxLineBytes: 8192 });
      await until(() => h.stderrText().includes("mock-mcp-server started"), "mock server startup");
      const payload = "x".repeat(4096);
      const line = JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/roots/list_changed",
        params: { payload },
      });
      const total = 500;
      for (let index = 0; index < total; index += 1) h.send(line);

      await settle(250);
      const buffered = h.proxy.child.stdin.writableLength;
      assert.ok(
        buffered > h.proxy.child.stdin.writableHighWaterMark,
        `the test must load the child buffer past its high-water mark: buffered=${buffered}, highWaterMark=${h.proxy.child.stdin.writableHighWaterMark}`,
      );
      assert.ok(
        buffered <= h.proxy.child.stdin.writableHighWaterMark + Buffer.byteLength(line) + 1,
      );
      assert.equal(h.proxy.child.exitCode, null, "child must still be alive while stalled");
      assert.equal(h.proxy.child.stdin.destroyed, false, "child stdin must remain open");

      h.resumeChildInput();
      await until(() => h.serverLog().length === total, "all stalled messages forwarded", 10_000);
      assert.equal(h.serverLog().length, total);
      assert.ok(
        h.serverLog().every((received) => received === line),
        "forwarded bytes must be exact",
      );
    },
  );
});

describe("proxy-generated output backpressure", () => {
  it("does not buffer unbounded synthetic denials when client stdout stalls", async () => {
    h = startHarness({});
    await until(() => h.stderrText().includes("mock-mcp-server started"), "mock server startup");
    h.pauseClientOutput();
    const batch = '[{"jsonrpc":"2.0","id":1,"method":"ping"}]';
    const total = 2000;
    for (let index = 0; index < total; index += 1) h.send(batch);

    await settle(250);
    const buffered = h.clientOutputBufferedBytes();
    assert.ok(
      buffered > h.clientOutputHighWaterBytes(),
      "the test must load client output past its high-water mark",
    );
    assert.ok(buffered <= h.clientOutputHighWaterBytes() + 256);

    h.resumeClientOutput();
    await until(() => h.clientLines.length === total, "all synthetic denials delivered", 10_000);
    assert.equal(h.clientLines.length, total);
  });

  it("coalesces diagnostics while client stderr is stalled", async () => {
    h = startHarness({});
    await until(() => h.stderrText().includes("mock-mcp-server started"), "mock server startup");
    h.pauseClientError();
    for (let index = 0; index < 5000; index += 1) h.send("not-json");

    await settle(250);
    const before = h.clientErrorBufferedBytes();
    for (let index = 0; index < 5000; index += 1) h.send("not-json");
    await settle(250);
    const after = h.clientErrorBufferedBytes();
    assert.ok(before <= h.clientErrorHighWaterBytes() + 256);
    assert.equal(after, before, "stalled diagnostic buffer must stop growing");
  });
});
