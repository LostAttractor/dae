// SPDX-License-Identifier: AGPL-3.0-only

package surge

import "testing"

func TestRuntimeTextDecoderInvalidUTF8(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(t.Context(), `
const cases = [
  [[0, 65, 0xc3, 0xa9], "\u0000Aé"],
  [[0x80, 0x80], "\ufffd\ufffd"],
  [[0xc0, 0xaf], "\ufffd\ufffd"],
  [[0xed, 0xa0, 0x80], "\ufffd\ufffd\ufffd"],
  [[0xe1, 0x80], "\ufffd"],
  [[0xe1, 0x80, 65], "\ufffdA"],
  [[0xef, 0xbf, 0xbd], "\ufffd"]
];
for (const [bytes, expected] of cases) {
  const got = new TextDecoder().decode(new Uint8Array(bytes));
  if (got !== expected) throw Error(JSON.stringify({bytes, got, expected}));
}
const bom = new Uint8Array([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, 65]);
if (new TextDecoder().decode(bom) !== "\ufeffA") throw Error("BOM stripping");
if (new TextDecoder("utf-8", {ignoreBOM:true}).decode(bom) !== "\ufeff\ufeffA") throw Error("BOM preservation");
const fatal = new TextDecoder("utf-8", {fatal:true});
if (fatal.decode(new Uint8Array([0xef, 0xbf, 0xbd])) !== "\ufffd") throw Error("valid replacement character");
let rejected = false;
try { fatal.decode(new Uint8Array([0xe1, 0x80])); } catch (e) { rejected = e instanceof TypeError; }
if (!rejected) throw Error("fatal decoder accepted truncated input");
$done();`, Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	result.Close()
}

func TestRuntimeTextEncoderInto(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(t.Context(), `
const encoder = new TextEncoder();
// encodeInto operates directly on the destination; encode is not a callback.
encoder.encode = () => { throw Error("encodeInto called an overridden encode"); };
const text = "Aé中🌏\ud800Z";
const bytes = [65, 0xc3, 0xa9, 0xe4, 0xb8, 0xad, 0xf0, 0x9f, 0x8c, 0x8f, 0xef, 0xbf, 0xbd, 90];
const boundaries = [[0,0], [1,1], [2,3], [3,6], [5,10], [6,13], [7,14]];
for (let size = 0; size <= bytes.length + 1; size++) {
  const target = new Uint8Array(size + 2).fill(0x55);
  let conversions = 0;
  const result = encoder.encodeInto({toString() { conversions++; return text; }}, target.subarray(1, size + 1));
  const [read, written] = boundaries.filter(([, n]) => n <= size).at(-1);
  if (conversions !== 1 || result.read !== read || result.written !== written) throw Error("partial encoding " + size);
  for (let i = 0; i < target.length; i++) {
    if (target[i] !== (i > 0 && i <= written ? bytes[i-1] : 0x55)) throw Error("destination bounds " + size);
  }
}
$done();`, Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	result.Close()
}
