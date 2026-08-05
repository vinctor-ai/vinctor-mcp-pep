import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { childEnv } from "../src/child_env.js";

describe("childEnv", () => {
  it("removes Vinctor credentials case-insensitively", () => {
    assert.deepEqual(
      childEnv({
        PATH: "/usr/bin",
        VINCTOR_PEP_KEY: "pep-secret",
        vinctor_subject_token: "subject-secret",
        Vinctor_Grant_Ref: "grant-secret",
      }),
      { PATH: "/usr/bin" },
    );
  });
});
