import jsdoc from "eslint-plugin-jsdoc";
import prettier from "eslint-config-prettier";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["**/dist/**", "**/node_modules/**", "**/coverage/**", "**/.turbo/**", "**/*.cjs"]
  },
  ...tseslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked.map((config) => ({
    ...config,
    files: ["packages/**/src/**/*.ts", "packages/**/test/**/*.ts", "examples/**/src/**/*.ts"],
    languageOptions: {
      ...config.languageOptions,
      parserOptions: {
        ...config.languageOptions?.parserOptions,
        project: [
          "./packages/*/tsconfig.test.json",
          "./packages/*/*/tsconfig.test.json",
          "./examples/*/tsconfig.json"
        ],
        tsconfigRootDir: import.meta.dirname
      }
    }
  })),
  {
    files: ["**/*.ts"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module"
    },
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
          destructuredArrayIgnorePattern: "^_"
        }
      ]
    }
  },
  {
    files: ["packages/**/src/**/*.ts"],
    rules: {
      "@typescript-eslint/consistent-type-imports": [
        "error",
        { prefer: "type-imports", fixStyle: "separate-type-imports" }
      ],
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/no-non-null-assertion": "error",
      "@typescript-eslint/no-unnecessary-condition": "error",
      "@typescript-eslint/prefer-readonly": "warn",
      "@typescript-eslint/switch-exhaustiveness-check": "error",
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["@aep-foundation/*/src", "@aep-foundation/*/src/*"],
              message:
                "Import from the package public API instead of another package's src internals."
            }
          ]
        }
      ]
    }
  },
  {
    files: ["packages/**/test/**/*.ts"],
    rules: {
      "@typescript-eslint/consistent-type-imports": [
        "error",
        { prefer: "type-imports", fixStyle: "separate-type-imports" }
      ],
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/no-unnecessary-condition": "error",
      "@typescript-eslint/switch-exhaustiveness-check": "error"
    }
  },
  {
    files: ["examples/**/src/**/*.ts"],
    rules: {
      "@typescript-eslint/consistent-type-imports": [
        "error",
        { prefer: "type-imports", fixStyle: "separate-type-imports" }
      ],
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/no-unnecessary-condition": "error",
      "@typescript-eslint/switch-exhaustiveness-check": "error",
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["@aep-foundation/*/src", "@aep-foundation/*/src/*"],
              message:
                "Import from the package public API instead of another package's src internals."
            }
          ]
        }
      ]
    }
  },
  {
    files: ["packages/**/src/**/*.ts"],
    plugins: { jsdoc },
    settings: {
      jsdoc: { mode: "typescript" }
    },
    rules: {
      "jsdoc/check-alignment": "error",
      "jsdoc/check-param-names": "warn",
      "jsdoc/check-tag-names": ["error", { definedTags: ["internal", "typeParam"] }],
      "jsdoc/empty-tags": "error",
      "jsdoc/multiline-blocks": "error",
      "jsdoc/no-blank-blocks": "error",
      "jsdoc/no-defaults": "warn",
      "jsdoc/no-multi-asterisks": "error",
      "jsdoc/no-types": "error",
      "jsdoc/require-asterisk-prefix": "error",
      "jsdoc/require-hyphen-before-param-description": ["warn", "always"]
    }
  },
  {
    files: ["packages/**/src/**/*.ts"],
    rules: {
      "no-console": "error"
    }
  },
  prettier
);
