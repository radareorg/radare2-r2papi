import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
    {
        ignores: [
            "node_modules/**",
            "build/**",
            "sync/**",
            "r2papi/**",
            "examples/**",
            "**/*.js",
            "**/*.d.ts"
        ]
    },
    js.configs.recommended,
    ...tseslint.configs.recommended,
    {
        languageOptions: {
            ecmaVersion: 2020,
            sourceType: "module"
        },
        rules: {
            "no-empty": ["error", { allowEmptyCatch: true }],
            "@typescript-eslint/no-this-alias": "off",
            "@typescript-eslint/no-explicit-any": "off",
            "@typescript-eslint/no-non-null-assertion": "off",
            "@typescript-eslint/no-unused-vars": "off"
        }
    }
);
