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
];
