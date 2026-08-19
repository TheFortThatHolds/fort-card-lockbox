// readUpstreamBody (build-item-52) -- mirrored across fort-card/worker, fort-card/last-mile, and
// this repo (the actual deployed lockbox for split-mode spaces) so /charge stays behavior-identical
// everywhere. .text() silently corrupts a non-UTF8 upstream response (audio/mpeg, image/*, etc.)
// before this worker ever wraps it in its own JSON envelope; this proves json/text still decode as
// before and anything else round-trips byte-for-byte through base64 instead of being mangled.
// Run: node test/binary-charge.test.mjs
import { readUpstreamBody } from "../src/worker.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

function fakeResp(contentType, bodyBytesOrText) {
  const isText = typeof bodyBytesOrText === "string";
  return {
    headers: { get: (h) => (h.toLowerCase() === "content-type" ? contentType : null) },
    async text() { return isText ? bodyBytesOrText : new TextDecoder().decode(bodyBytesOrText); },
    async arrayBuffer() {
      const bytes = isText ? new TextEncoder().encode(bodyBytesOrText) : bodyBytesOrText;
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    },
  };
}

(async () => {
  {
    const r = await readUpstreamBody(fakeResp("application/json", '{"ok":true}'));
    ok(typeof r === "object" && r.ok === true, "json content-type parses to an object");
  }
  {
    const r = await readUpstreamBody(fakeResp("text/plain", "hello"));
    ok(r === "hello", "text/plain stays a plain string");
  }
  {
    // this exact shape (0xff/0x80/0xfe -- not valid standalone UTF-8) is what a real ElevenLabs
    // audio/mpeg response looks like, and what production was observed to corrupt via .text().
    const original = new Uint8Array([0x49, 0x44, 0x33, 0xff, 0x80, 0x00, 0x7f, 0xfe]);
    const r = await readUpstreamBody(fakeResp("audio/mpeg", original));
    ok(r && r._binary === true && r.content_type === "audio/mpeg", "binary response flagged with real content-type");
    const decoded = r ? Uint8Array.from(atob(r.base64), (c) => c.charCodeAt(0)) : null;
    ok(decoded && decoded.length === original.length && decoded.every((b, i) => b === original[i]),
      "binary bytes survive round-trip byte-for-byte through base64");
  }

  console.log(`\nbinary-charge (lockbox): ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
})();
