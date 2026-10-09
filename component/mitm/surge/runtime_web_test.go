// SPDX-License-Identifier: AGPL-3.0-only

package surge

import "testing"

func TestRuntimeURLSearchParamsContracts(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(t.Context(), `
function assert(value) { if (!value) throw Error("URLSearchParams contract"); }
const p = new URLSearchParams("q=100%&bad=%C3%28&bom=%EF%BB%BFx&a=1&a=2");
assert(p.get("q") === "100%" && p.get("bad") === "\uFFFD(" && p.get("bom") === "\uFEFFx");
p.delete("a", "1"); assert(p.getAll("a").join() === "2" && !p.has("a", "1") && p.has("a", "2"));
const live = new URLSearchParams("a=1&b=2"), iterator = live.entries();
assert(iterator.next().value.join() === "a,1");
live.delete("a"); live.append("c", "3");
assert(iterator.next().value.join() === "c,3");
const unicode = new URLSearchParams({x:"\uD800"});
assert(unicode.toString() === "x=%EF%BF%BD");
assert(new URLSearchParams(null).size === 0);
$done();`, Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	result.Close()
}
