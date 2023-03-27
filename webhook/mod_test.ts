import * as mod from "./mod.ts";
import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.178.0/testing/asserts.ts";

Deno.test("splitHeader splits headers right", () => {
  const result = mod.splitHeader(
    "t=1663781880,v1=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  );
  assertEquals(result, {
    t: "1663781880",
    v1: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  });
});

Deno.test("validateSignature works", async () => {
  assert(
    await mod.validateSignature(
      "hi there",
      "d4f6f042ffb3ed59cf023a75065ea6c543ec034e765130eb5249a7f0eb1692f6",
      "foobar",
    ),
    "hmac signing doesn't work",
  );
});
