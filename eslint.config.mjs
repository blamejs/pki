// ESLint config for the @blamejs/pki toolkit + examples.
//
// Posture: catch bug-class problems (undefined references, unused
// variables, redeclarations, equality slips, control-flow issues).
// Don't enforce style ("var" vs "const", arrow-vs-function, etc.) —
// the codebase has settled conventions documented in CONTRIBUTING.md
// that ESLint shouldn't second-guess.
//
// Target: Node 24 LTS, CommonJS modules, ES2024 syntax. Vendored
// dependencies under lib/vendor/ and any node_modules are excluded.
//
// Standalone (no @eslint/js / globals npm dependency) so this lints
// cleanly via `npx eslint@latest` without resolving extra peer deps.

const NODE_GLOBALS = {
  // CommonJS module system
  module:           "readonly",
  require:          "readonly",
  exports:          "writable",
  __dirname:        "readonly",
  __filename:       "readonly",
  // Node runtime
  process:          "readonly",
  Buffer:           "readonly",
  global:           "readonly",
  globalThis:       "readonly",
  console:          "readonly",
  setTimeout:       "readonly",
  setInterval:      "readonly",
  setImmediate:     "readonly",
  clearTimeout:     "readonly",
  clearInterval:    "readonly",
  clearImmediate:   "readonly",
  queueMicrotask:   "readonly",
  performance:      "readonly",
  structuredClone:  "readonly",
  // Web-platform APIs that Node 24 ships
  fetch:            "readonly",
  crypto:           "readonly",
  URL:              "readonly",
  URLSearchParams:  "readonly",
  TextEncoder:      "readonly",
  TextDecoder:      "readonly",
  AbortController:  "readonly",
  AbortSignal:      "readonly",
  Event:            "readonly",
  EventTarget:      "readonly",
  Blob:             "readonly",
  // Modern intrinsics
  BigInt:           "readonly",
  Atomics:          "readonly",
  SharedArrayBuffer:"readonly",
  WeakRef:          "readonly",
  FinalizationRegistry: "readonly",
};

const COMMON_RULES = {
  // Bug-class rules
  "no-undef":                  "error",
  "no-redeclare":              "error",
  "no-const-assign":           "error",
  "no-delete-var":             "error",
  "no-shadow-restricted-names":"error",
  "no-global-assign":          "error",
  "no-import-assign":          "error",
  "no-func-assign":            "error",
  "no-class-assign":           "error",
  "no-this-before-super":      "error",
  "no-ex-assign":              "error",
  "no-cond-assign":            ["error", "except-parens"],
  "no-self-assign":            "error",
  "no-self-compare":           "error",
  "no-unreachable":            "error",
  "no-unsafe-finally":         "error",
  "no-unsafe-negation":        "error",
  "no-unsafe-optional-chaining": "error",
  "no-fallthrough":            "error",
  "no-async-promise-executor": "error",
  "use-isnan":                 "error",
  "valid-typeof":              "error",
  "getter-return":             "error",
  "no-compare-neg-zero":       "error",
  "no-constant-condition":     ["error", { checkLoops: false }],
  "no-constant-binary-expression": "error",
  "no-dupe-keys":              "error",
  "no-dupe-args":              "error",
  "no-dupe-else-if":           "error",
  "no-duplicate-case":         "error",
  "no-sparse-arrays":          "error",
  "no-invalid-regexp":         "error",
  "no-misleading-character-class": "error",
  "no-regex-spaces":           "error",
  "no-useless-backreference":  "error",
  "no-control-regex":          "error",
  "no-irregular-whitespace":   "error",
  "no-octal":                  "error",
  "no-debugger":               "error",
  "no-prototype-builtins":     "error",
  // Strict equality — `null` allowed for the `== null` / `!= null`
  // null-or-undefined idiom; everything else must use `===` / `!==`.
  "eqeqeq":                    ["error", "always", { null: "ignore" }],
  "no-throw-literal":          "error",
  "no-promise-executor-return":"error",
  "default-case":              "error",
  "no-loss-of-precision":      "error",

  // Hygiene rules — code clarity, dead-code removal.
  // A value assigned and then overwritten before any read is dead code that
  // usually marks a refactor leftover or a wrong-variable slip.
  "no-useless-assignment":     "error",
  "no-unused-vars":            ["error", {
    args:                      "none",
    varsIgnorePattern:         "^_",
    caughtErrors:              "all",
    caughtErrorsIgnorePattern: "^_",
    destructuredArrayIgnorePattern: "^_",
  }],
  "no-useless-escape":         "error",
  "no-empty":                  ["error", { allowEmptyCatch: true }],
  "no-extra-boolean-cast":     "error",
  "no-unused-expressions":     ["error", { allowShortCircuit: true, allowTernary: true }],
  "no-unused-private-class-members": "error",
};

// A destructuring pattern that BINDS `push` or `unshift` hands the module the storing form of
// append, which stores at an index and therefore runs a setter inherited from the prototype chain.
// `guard-intrinsic` exports neither name, so a binding is the way one would be obtained.
//
// This is a rule rather than a text search because the question is grammatical and a text search
// cannot answer it. The decisive case is a method's parameter list: `m({ push: p }) {}` and the call
// `m({ push: 1 })` are the same characters, so no lexical walk can tell a binding from an argument,
// and widening one to catch the first reports every call of the second. The parser separates them by
// node type. An `ObjectPattern` is only produced where the object IS a pattern: a declaration, an
// assignment target however deeply nested, a for-of or for-in header, a catch parameter, and a
// parameter list of any function, generator, method or arrow. An object LITERAL is an
// `ObjectExpression`, a different node, so a literal cannot match however it is written, including
// one used as a default inside a real pattern.
//
// A key is read as the name it denotes: an identifier key, a quoted key, a key written with an
// escape, and a computed key whose expression is a literal all arrive decoded. A computed key built
// at runtime cannot be answered statically and is left alone.
const APPEND_BINDING_NAMES = new Set(["push", "unshift"]);

// A variable's value when the program determines it: exactly one write, and that write a string
// literal. `var` is the convention here and a `var` can be reassigned, so the single-write test is
// what makes reading the initializer sound rather than the declaration keyword.
function singleWriteStringValue(node, sourceCode) {
  if (node.type !== "Identifier") return null;
  let scope = sourceCode.getScope(node);
  while (scope) {
    const variable = scope.variables.find((v) => v.name === node.name);
    if (variable) {
      const writes = variable.references.filter((r) => r.isWrite());
      if (writes.length !== 1) return null;
      const written = writes[0].writeExpr;
      if (!written || written.type !== "Literal" || typeof written.value !== "string") return null;
      return written.value;
    }
    scope = scope.upper;
  }
  return null;
}

function staticKeyName(key, computed, sourceCode) {
  if (!key) return null;
  if (!computed && key.type === "Identifier") return key.name;
  if (key.type === "Literal") return typeof key.value === "string" ? key.value : null;
  if (key.type === "TemplateLiteral" && key.expressions.length === 0 && key.quasis.length === 1) {
    return key.quasis[0].value.cooked;
  }
  // A computed key naming a variable, which is the obvious way to write the name without writing it:
  // `var PUSH = "push"; var { [PUSH]: p } = Array.prototype;`.
  if (computed && key.type === "Identifier") return singleWriteStringValue(key, sourceCode);
  return null;
}

const noStoringAppendBinding = {
  meta: {
    type: "problem",
    schema: [],
    messages: {
      bound: "`{{name}}` is the storing form of append: a store at an index runs a setter inherited " +
        "from the prototype chain, which takes the element being appended. Bind nothing here and " +
        "call `intrinsic.append(list, value)` or `guard.list.append(list, value)`, which define the " +
        "index instead.",
    },
  },
  create(context) {
    const sourceCode = context.sourceCode;
    return {
      ObjectPattern(node) {
        for (const prop of node.properties) {
          if (prop.type !== "Property") continue;
          const name = staticKeyName(prop.key, prop.computed, sourceCode);
          if (name === null || !APPEND_BINDING_NAMES.has(name)) continue;
          context.report({ node: prop, messageId: "bound", data: { name } });
        }
      },
    };
  },
};

const pkiPlugin = { rules: { "no-storing-append-binding": noStoringAppendBinding } };

export default [
  {
    ignores: [
      "**/node_modules/**",
      "lib/vendor/**",
      "examples/wiki/public/vendor/**",
      "examples/wiki/public/dist/**",
      "**/data/**",
      "**/data-e2e/**",
      "**/.git/**",
      ".test-output/**",
      ".scratch/**",
      // Untracked working directories. They never exist in CI, so linting them locally
      // makes a full-tree run disagree with the gate it is meant to reproduce -- which
      // invites scoping the local run to a subset and missing what CI will catch.
      ".references/**",
      ".claude/**",
    ],
  },
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType:  "commonjs",
      globals:     NODE_GLOBALS,
    },
    rules: COMMON_RULES,
  },
  {
    files: ["**/*.mjs"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType:  "module",
      globals:     NODE_GLOBALS,
    },
    rules: COMMON_RULES,
  },
  // Scoped to the shipped library, which is where a bound storing append would decide what a parse
  // or an encode reads back. Test and example code may bind what it likes.
  {
    files: ["lib/**/*.js", "lib/**/*.mjs"],
    plugins: { pki: pkiPlugin },
    rules: { "pki/no-storing-append-binding": "error" },
  },
];
