// @ts-check
import js from "@eslint/js";
import tsParser from "@typescript-eslint/parser";
import globals from "globals";

export default [
  { ignores: ["**/node_modules/**", "**/dist/**", "**/test-results/**", "docs/**"] },
  js.configs.recommended,
  {
    // TypeScript's compiler owns undefined-variable and unused-symbol checks;
    // core JS versions misfire on types, ambient globals and interface params.
    rules: { "no-undef": "off", "no-unused-vars": "off" },
  },
  {
    // TS files: parser only (no type-aware rules — keeps lint fast and TS-version agnostic).
    files: ["**/*.ts", "**/*.tsx"],
    languageOptions: {
      parser: tsParser,
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
  },
  {
    // R-19 (§9): session secrets and tokens must never touch web storage.
    files: ["apps/web/src/**/*.{ts,tsx}"],
    languageOptions: { parser: tsParser, parserOptions: { ecmaFeatures: { jsx: true } }, globals: globals.browser },
    rules: {
      "no-restricted-globals": [
        "error",
        { name: "localStorage", message: "R-19: no secrets or tokens in web storage. Keep auth state in memory + HttpOnly cookie." },
        { name: "sessionStorage", message: "R-19: no secrets or tokens in web storage." },
      ],
      "no-restricted-properties": [
        "error",
        { object: "window", property: "localStorage", message: "R-19: no secrets or tokens in web storage." },
        { object: "window", property: "sessionStorage", message: "R-19: no secrets or tokens in web storage." },
      ],
    },
  },
  {
    files: ["apps/api/**/*.ts", "packages/session/**/*.ts"],
    languageOptions: { parser: tsParser, globals: globals.node },
  },
];
