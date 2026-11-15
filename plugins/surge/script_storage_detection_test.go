// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"strconv"
	"strings"
	"testing"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

func BenchmarkScriptUsesPersistentStore(b *testing.B) {
	const fragment = `(() => { 'use strict'; const local = {read() { return "text" }}; function inner($persistentStore) { return $persistentStore.read("key") } return local.read() })();`
	for _, count := range []int{100, 1000, 10000, 100000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			source := strings.Repeat(fragment, count) + `$persistentStore.read("key");`
			b.SetBytes(int64(len(source)))
			b.ReportAllocs()
			for b.Loop() {
				if got, err := scriptUsesPersistentStore(source); err != nil || !got {
					b.Fatalf("detection = %t, %v; want true, nil", got, err)
				}
			}
		})
	}
}

func TestScriptStorageParserDeclarations(t *testing.T) {
	program, err := parser.ParseFile(nil, "", `if (false) { var root; } let lexical; function f() { for (var local of values) {} let other; }`, 0, parser.WithDisableSourceMaps)
	if err != nil {
		t.Fatal(err)
	}
	if len(program.DeclarationList) != 1 || program.DeclarationList[0].List[0].Target.(*ast.Identifier).Name != "root" {
		t.Fatal("program DeclarationList must contain hoisted var bindings only")
	}
	function := program.Body[2].(*ast.FunctionDeclaration).Function
	if len(function.DeclarationList) != 1 || function.DeclarationList[0].List[0].Target.(*ast.Identifier).Name != "local" {
		t.Fatal("function DeclarationList must contain nested var bindings without leaking them to the program")
	}
}

func TestScriptStorageParserDisablesSourceMapLoader(t *testing.T) {
	calls := 0
	loader := parser.WithSourceMapLoader(func(string) ([]byte, error) {
		calls++
		return nil, nil
	})
	for _, url := range []string{"local.map", "file:///unused.map", "https://example.invalid/unused.map"} {
		source := "$persistentStore.read();\n//# sourceMappingURL=" + url
		if _, err := parser.ParseFile(nil, "input.js", source, 0, loader); err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Fatalf("enabled source maps called loader %d times; want 1", calls)
		}
		if _, err := parser.ParseFile(nil, "input.js", source, 0, loader, parser.WithDisableSourceMaps); err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Fatal("disabled source maps must not call the loader")
		}
		if got, err := scriptUsesPersistentStore(source); err != nil || !got {
			t.Fatalf("source map directive changed detection: %t, %v", got, err)
		}
		calls = 0
	}
}

func TestScriptStorageParseErrors(t *testing.T) {
	for _, source := range []string{
		`$persistentStore.read(`,
		`$persistentStore.read(); const = ;`,
		`$persistentStore.read(); const x: number = 0;`,
		`$persistentStore.read(); import value from "module";`,
	} {
		if got, err := scriptUsesPersistentStore(source); err == nil || got {
			t.Fatalf("invalid or unsupported syntax must return false and an error: %q: %t, %v", source, got, err)
		}
	}
}

func TestScriptUsesPersistentStore(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   bool
	}{
		{"empty", ``, false},
		{"direct read", `$persistentStore.read("key")`, true},
		{"direct write", `$persistentStore.write("value", "key")`, true},
		{"literal read", `$persistentStore['read']("key")`, true},
		{"escaped method", `$persistentStore["\x72ead"]("key")`, true},
		{"parenthesized object", `($persistentStore)["read"]("key")`, true},
		{"parenthesized", `($persistentStore.read)("key")`, true},
		{"optional object", `$persistentStore?.read("key")`, true},
		{"optional method", `$persistentStore.read?.("key")`, true},
		{"optional literal", `$persistentStore?.["write"]?.(null, "key")`, true},
		{"optional result", `$persistentStore.read("key")?.value`, true},
		{"method reference", `$persistentStore.read`, false},
		{"constructor", `new $persistentStore.read("key")`, false},
		{"dynamic property", `$persistentStore[method]("key")`, false},
		{"computed property", `$persistentStore["re" + "ad"]("key")`, false},
		{"other method", `$persistentStore.remove("key")`, false},
		{"alias", `const store = $persistentStore; store.read("key")`, false},
		{"global property", `globalThis.$persistentStore.read("key")`, false},
		{"another object", `other.$persistentStore.read("key")`, false},
		{"tagged method", "$persistentStore.read`key`", false},
		{"template text", "`$persistentStore.read()`", false},
		{"template interpolation", "`prefix ${$persistentStore.read('key')}`", true},
		{"tagged interpolation", "tag`prefix ${$persistentStore.write(null, 'key')}`", true},
		{"comments between tokens", `$persistentStore /*comment*/ . read /*comment*/ ("key")`, true},
		{"block comment", `/* $persistentStore.read() */`, false},
		{"unreachable call", `if (false) $persistentStore.read("key")`, true},
		{"argument call", `consume($persistentStore.read("key"))`, true},
		{"constructor argument", `new Thing($persistentStore.read("key"))`, true},
		{"binary and conditional", `flag && (other ? 0 : $persistentStore.read("key"))`, true},
		{"object value", `({value: $persistentStore.read("key")})`, true},
		{"object key", `({[$persistentStore.read("key")]: 0})`, true},
		{"object method", `({read() { return $persistentStore.read("key") }})`, true},
		{"object getter", `({get value() { return $persistentStore.read("key") }})`, true},
		{"array spread", `[...$persistentStore.read("key")]`, true},
		{"object spread", `({...$persistentStore.read("key")})`, true},
		{"sequence", `(0, $persistentStore.read("key"))`, true},
		{"unary", `void $persistentStore.read("key")`, true},
		{"await", `async function f() { return await $persistentStore.read("key") }`, true},
		{"yield", `function* f() { yield $persistentStore.read("key") }`, true},
		{"literal write", `$persistentStore["write"](null, "key")`, true},
		{"optional call", `$persistentStore?.read?.("key")`, true},
		{"text only", "// $persistentStore.read()\n'$persistentStore.write()'; /\\$persistentStore.read\\(/;", false},
		{"parameter shadow", `(function($persistentStore) { $persistentStore.read("key") })`, false},
		{"inner shadow preserves outer", `{ let $persistentStore; $persistentStore.read() } $persistentStore.read()`, true},
		{"var hoisting", `function f() { $persistentStore.read(); if (false) { var $persistentStore; } }`, false},
		{"lexical TDZ", `$persistentStore.read(); let $persistentStore;`, false},
		{"top-level var hoist", `$persistentStore.read(); if (false) { var $persistentStore; }`, true},
		{"global var before call", `var $persistentStore; $persistentStore.read()`, true},
		{"global var after call", `$persistentStore.read(); var $persistentStore;`, true},
		{"strict global var before call", `'use strict'; var $persistentStore; $persistentStore.read()`, true},
		{"strict global var after call", `'use strict'; $persistentStore.read(); var $persistentStore;`, true},
		{"strict function var shadow", `function f() { 'use strict'; var $persistentStore; $persistentStore.read() }`, false},
		{"nested var does not leak", `function f() { var $persistentStore; } $persistentStore.read()`, true},
		{"nested var initializer does not leak", `function f() { var $persistentStore = {}; } $persistentStore.read()`, true},
		{"nested shadow does not leak", `function f($persistentStore) { $persistentStore.read() } $persistentStore.read()`, true},
		{"parent lexical discovered later", `function f() { $persistentStore.read() } const $persistentStore = {};`, false},
		{"nested function inherits binding", `function f($persistentStore) { return () => $persistentStore.read() }`, false},
		{"arrow parameter", `($persistentStore) => $persistentStore.read()`, false},
		{"arrow default", `(value = $persistentStore.read()) => value`, true},
		{"arrow var hoist", `() => { $persistentStore.read(); var $persistentStore; }`, false},
		{"rest parameter", `(...$persistentStore) => $persistentStore.read()`, false},
		{"parameter TDZ", `function f(value = $persistentStore.read(), $persistentStore) {}`, false},
		{"parameter before body var", `function f(value = $persistentStore.read()) { var $persistentStore; }`, true},
		{"parameter before body lexical", `function f(value = $persistentStore.read()) { let $persistentStore; }`, true},
		{"parameter before body function", `function f(value = $persistentStore.read()) { function $persistentStore() {} }`, true},
		{"function declaration hoist", `$persistentStore.read(); function $persistentStore() {}`, false},
		{"named function expression", `(function $persistentStore() { $persistentStore.read() })`, false},
		{"function expression name does not leak", `(function $persistentStore() {}); $persistentStore.read()`, true},
		{"strict block function", `'use strict'; { $persistentStore.read(); function $persistentStore() {} }`, false},
		{"strict block function does not leak", `'use strict'; { function $persistentStore() {} } $persistentStore.read()`, true},
		{"sloppy block function hoist", `$persistentStore.read(); { function $persistentStore() {} }`, false},
		{"parenthesized string is not strict", `('use strict'); { function $persistentStore() {} } $persistentStore.read()`, false},
		{"parenthesized string ends directives", `('other'); 'use strict'; { function $persistentStore() {} } $persistentStore.read()`, false},
		{"empty statement ends directives", `; 'use strict'; { function $persistentStore() {} } $persistentStore.read()`, false},
		{"strict directive after comments", `/*comment ( */ 'other'; /*comment*/ 'use strict'; { function $persistentStore() {} } $persistentStore.read()`, true},
		{"function parenthesized string", `function f() { ('use strict'); { function $persistentStore() {} } $persistentStore.read() }`, false},
		{"inherited strict mode", `'use strict'; function f() { { function $persistentStore() {} } $persistentStore.read() }`, true},
		{"block async function stays lexical", `{ async function $persistentStore() {} } $persistentStore.read()`, true},
		{"block generator stays lexical", `{ function* $persistentStore() {} } $persistentStore.read()`, true},
		{"outer lexical blocks Annex B", `{ let $persistentStore; { function $persistentStore() {} } } $persistentStore.read()`, true},
		{"later lexical blocks Annex B", `{ { function $persistentStore() {} } let $persistentStore; } $persistentStore.read()`, true},
		{"strict function directive", `function f() { 'other'; 'use strict'; { function $persistentStore() {} } $persistentStore.read() }`, true},
		{"class TDZ", `$persistentStore.read(); class $persistentStore {}`, false},
		{"class expression name", `(class $persistentStore { m() { $persistentStore.read() } })`, false},
		{"class expression extends TDZ", `(class $persistentStore extends $persistentStore.read() {})`, false},
		{"class expression name does not leak", `(class $persistentStore {}); $persistentStore.read()`, true},
		{"class extends", `class C extends $persistentStore.read() {}`, true},
		{"class field", `class C { field = $persistentStore.read() }`, true},
		{"class computed method", `class C { [$persistentStore.read()]() {} }`, true},
		{"class computed field", `class C { [$persistentStore.read()] = 0 }`, true},
		{"class method parameter", `class C { m($persistentStore) { $persistentStore.read() } }`, false},
		{"class private field", `class C { #value = $persistentStore.read(); m() { return this.#value } }`, true},
		{"class static block var", `class C { static { $persistentStore.read(); var $persistentStore; } }`, false},
		{"class static var does not leak", `class C { static { var $persistentStore; } field = $persistentStore.read() }`, true},
		{"class static var initializer does not leak", `class C { static { var $persistentStore = {}; } } $persistentStore.read()`, true},
		{"class strict block function", `class C { static { { function $persistentStore() {} } $persistentStore.read() } }`, true},
		{"array destructuring", `const [$persistentStore] = source; $persistentStore.read()`, false},
		{"object shorthand destructuring", `let {$persistentStore} = source; $persistentStore.read()`, false},
		{"nested destructuring", `const {x: [,$persistentStore = {}]} = source; $persistentStore.read()`, false},
		{"destructured rest", `const {...$persistentStore} = source; $persistentStore.read()`, false},
		{"array rest", `let [first, ...$persistentStore] = source; $persistentStore.read()`, false},
		{"destructured parameter", `function f({x: $persistentStore}) { $persistentStore.read() }`, false},
		{"destructured default shadows", `function f({$persistentStore = $persistentStore.read()}) {}`, false},
		{"destructured key is not binding", `const {$persistentStore: value} = source; $persistentStore.read()`, true},
		{"destructured computed key call", `const {[$persistentStore.read()]: value} = source;`, true},
		{"destructured default call", `const {value = $persistentStore.read()} = source;`, true},
		{"catch binding", `try {} catch ($persistentStore) { $persistentStore.read() }`, false},
		{"catch destructuring", `try {} catch ({x: [$persistentStore]}) { $persistentStore.read() }`, false},
		{"catch default", `try {} catch ({x = $persistentStore.read()}) {}`, true},
		{"catch binding does not leak", `try {} catch ($persistentStore) {} $persistentStore.read()`, true},
		{"catch var initializer stays local", `try { throw null; } catch ($persistentStore) { var $persistentStore = {}; } $persistentStore.read()`, true},
		{"catch for var stays local", `try { throw null; } catch ($persistentStore) { for (var $persistentStore of [{}]) {} } $persistentStore.read()`, true},
		{"optional catch binding", `try {} catch { $persistentStore.read() }`, true},
		{"simple catch permits Annex B", `try {} catch ($persistentStore) { { function $persistentStore() {} } } $persistentStore.read()`, false},
		{"pattern catch blocks Annex B", `try {} catch ([$persistentStore]) { { function $persistentStore() {} } } $persistentStore.read()`, true},
		{"finally call", `try {} finally { $persistentStore.read() }`, true},
		{"throw call", `throw $persistentStore.read()`, true},
		{"for lexical TDZ", `for (let $persistentStore = $persistentStore.read(); false;) {}`, false},
		{"for lexical does not leak", `for (let $persistentStore;;) { break; } $persistentStore.read()`, true},
		{"for var hoist", `$persistentStore.read(); for (var $persistentStore;;) { break; }`, true},
		{"for var before call", `for (var $persistentStore;;) { break; } $persistentStore.read()`, true},
		{"for var source call", `for (var item of $persistentStore.read()) {}`, true},
		{"for var destructured default call", `for (var {value = $persistentStore.read()} of values) {}`, true},
		{"for of TDZ", `for (let $persistentStore of $persistentStore.read()) {}`, false},
		{"for in TDZ", `for (const $persistentStore in $persistentStore.read()) {}`, false},
		{"for of destructuring", `for (const {x: $persistentStore} of values) $persistentStore.read()`, false},
		{"for of source", `for (const item of $persistentStore.read()) {}`, true},
		{"for update", `for (;;$persistentStore.read()) { break; }`, true},
		{"for initializer", `for ($persistentStore.read();;) { break; }`, true},
		{"switch shared TDZ", `switch (value) { case 0: $persistentStore.read(); break; default: let $persistentStore; }`, false},
		{"switch discriminant outside scope", `switch ($persistentStore.read()) { default: let $persistentStore; }`, true},
		{"switch case expression", `switch (value) { case $persistentStore.read(): break; }`, true},
		{"while body", `while (true) { $persistentStore.read(); break; }`, true},
		{"do while test", `do {} while ($persistentStore.read());`, true},
		{"label", `outer: { $persistentStore.read(); break outer; }`, true},
		{"eval invalidates", `eval("anything"); $persistentStore.read()`, false},
		{"indirect eval invalidates", `(0, eval)("anything"); $persistentStore.read()`, false},
		{"optional eval invalidates", `eval?.("anything"); $persistentStore.read()`, false},
		{"member eval invalidates", `globalThis["eval"]("anything"); $persistentStore.read()`, false},
		{"with invalidates", `with (object) { $persistentStore.read() }`, false},
		{"later with invalidates", `$persistentStore.read(); with (object) {}`, false},
		{"rewrite invalidates", `$persistentStore.read = function() {}; $persistentStore.read()`, false},
		{"later rewrite invalidates", `$persistentStore.read(); $persistentStore = other`, false},
		{"global var initializer invalidates", `var $persistentStore = {}; $persistentStore.read()`, false},
		{"later global var initializer invalidates", `$persistentStore.read(); var $persistentStore = {};`, false},
		{"strict global var initializer invalidates", `'use strict'; var $persistentStore = {}; $persistentStore.read()`, false},
		{"global var array destructuring invalidates", `var [$persistentStore] = values; $persistentStore.read()`, false},
		{"global var object destructuring invalidates", `var {$persistentStore} = value; $persistentStore.read()`, false},
		{"global var nested destructuring invalidates", `var {x: [$persistentStore = {}]} = value; $persistentStore.read()`, false},
		{"global var initializer call", `var value = $persistentStore.read();`, true},
		{"global var destructured default call", `var {value = $persistentStore.read()} = source;`, true},
		{"for var initializer invalidates", `for (var $persistentStore = {};;) { break; } $persistentStore.read()`, false},
		{"for in var invalidates", `for (var $persistentStore in values) {} $persistentStore.read()`, false},
		{"for of var invalidates", `for (var $persistentStore of values) {} $persistentStore.read()`, false},
		{"for in var destructuring invalidates", `for (var [$persistentStore] in values) {} $persistentStore.read()`, false},
		{"for of var destructuring invalidates", `for (var {x: $persistentStore} of values) {} $persistentStore.read()`, false},
		{"literal rewrite invalidates", `$persistentStore["read"] = other; $persistentStore.read()`, false},
		{"dynamic rewrite invalidates", `$persistentStore[method] = other; $persistentStore.read()`, false},
		{"compound rewrite invalidates", `$persistentStore ||= other; $persistentStore.read()`, false},
		{"destructured rewrite invalidates", `({x: $persistentStore.read} = source); $persistentStore.read()`, false},
		{"array rewrite invalidates", `[$persistentStore] = source; $persistentStore.read()`, false},
		{"deletion invalidates", `delete $persistentStore.read; $persistentStore.read()`, false},
		{"increment invalidates", `$persistentStore.read++; $persistentStore.read()`, false},
		{"for of assignment invalidates", `for ($persistentStore of values) {} $persistentStore.read()`, false},
		{"for in assignment invalidates", `for ($persistentStore.read in values) {} $persistentStore.read()`, false},
		{"defineProperty invalidates", `Object.defineProperty($persistentStore, "read", {}); $persistentStore.read()`, false},
		{"defineProperties invalidates", `Object.defineProperties($persistentStore, {}); $persistentStore.read()`, false},
		{"assign invalidates", `Object.assign($persistentStore, other); $persistentStore.read()`, false},
		{"Reflect set invalidates", `Reflect.set($persistentStore, "write", other); $persistentStore.read()`, false},
		{"prototype invalidates", `Object.setPrototypeOf($persistentStore, other); $persistentStore.read()`, false},
		{"getter invalidates", `$persistentStore.__defineGetter__("read", other); $persistentStore.read()`, false},
		{"shadowed rewrite does not invalidate", `function f($persistentStore) { $persistentStore.read = other } $persistentStore.read()`, true},
		{"shadowed property rewrite does not invalidate", `{ const $persistentStore = {}; Object.defineProperty($persistentStore, "read", {}); } $persistentStore.read()`, true},
		{"declaration property is not rewrite", `const {x: value = $persistentStore.read()} = source;`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scriptUsesPersistentStore(tt.source)
			if err != nil || got != tt.want {
				t.Fatalf("scriptUsesPersistentStore() = %t, %v; want %t, nil", got, err, tt.want)
			}
		})
	}
}
