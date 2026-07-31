import js from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'
import functional from 'eslint-plugin-functional'
import vitest from '@vitest/eslint-plugin'

export default tseslint.config(
  { ignores: ['dist/', 'coverage/', 'node_modules/', '*.config.*', '**/*.d.ts'] },

  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,

  // ── All TypeScript files ──────────────────────────────────────────────
  {
    languageOptions: {
      globals: globals.node,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // typescript-type-safety: type over interface, inline type imports
      '@typescript-eslint/consistent-type-definitions': ['error', 'type'],
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'inline-type-imports' },
      ],
      '@typescript-eslint/switch-exhaustiveness-check': 'error',
      '@typescript-eslint/prefer-readonly': 'error',
      '@typescript-eslint/method-signature-style': ['error', 'property'],
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      '@typescript-eslint/no-unnecessary-type-conversion': 'error',

      // TS compiler handles these — disable base JS versions
      'no-undef': 'off',

      // dev-coding-practices: functional-lite style
      'no-console': 'warn',
      'no-loop-func': 'error',
      'prefer-arrow-callback': 'error',
      'prefer-const': 'error',
      'prefer-spread': 'error',
      'prefer-template': 'error',
      'prefer-destructuring': [
        'error',
        { array: true, object: true },
        { enforceForRenamedProperties: true },
      ],
      'no-var': 'error',
      'no-param-reassign': 'error',
      'no-restricted-syntax': [
        'error',
        'SwitchStatement',
        {
          selector: 'Literal[value=null]',
          message: 'Use undefined instead of null (dev-coding-practices)',
        },
        {
          selector: 'TSNullKeyword',
          message: 'Use undefined instead of null in types (dev-coding-practices)',
        },
      ],
      'object-shorthand': ['error', 'always'],
      'no-useless-return': 'error',
      'no-useless-computed-key': 'error',
      'no-useless-rename': 'error',
    },
  },

  // ── Source files (non-test): functional rules ─────────────────────────
  {
    files: ['src/**/*.ts'],
    ignores: ['src/**/*.test.ts'],
    plugins: { functional },
    rules: {
      'functional/no-classes': 'error',
      'functional/no-class-inheritance': 'error',
      'functional/no-this-expressions': 'error',
      'functional/no-mixed-types': 'error',
      'functional/no-let': 'error',
      'functional/no-loop-statements': 'error',
      'functional/readonly-type': 'error',
      'functional/functional-parameters': 'error',
      'functional/prefer-property-signatures': 'error',
      'functional/prefer-tacit': 'error',
      'functional/immutable-data': ['error', { ignoreClasses: true }],
      'functional/no-conditional-statements': 'error',
      'functional/no-expression-statements': 'error',
      'functional/no-return-void': 'error',
      'functional/no-throw-statements': 'error',
      'functional/no-try-statements': 'error',
      'functional/no-promise-reject': 'error',
    },
  },

  // ── Test files: vitest rules + relaxed type safety ────────────────────
  {
    files: ['src/**/*.test.ts'],
    ...vitest.configs.recommended,
    rules: {
      ...vitest.configs.recommended.rules,

      // typescript-type-safety: relax strict checks in tests
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      'no-restricted-syntax': 'off',

      // test-code-quality: vitest rules
      'vitest/consistent-test-it': ['error', { fn: 'it' }],
      'vitest/consistent-test-filename': 'error',
      'vitest/require-top-level-describe': 'error',
      'vitest/require-hook': 'error',
      'vitest/no-duplicate-hooks': 'error',
      'vitest/prefer-hooks-in-order': 'error',
      'vitest/hoisted-apis-on-top': 'error',
      'vitest/no-test-prefixes': 'error',
      'vitest/prefer-to-be': 'error',
      'vitest/prefer-to-have-length': 'error',
      'vitest/prefer-to-have-been-called-times': 'error',
      'vitest/prefer-equality-matcher': 'error',
      'vitest/prefer-strict-equal': 'error',
      'vitest/prefer-mock-promise-shorthand': 'error',
      'vitest/prefer-expect-resolves': 'error',
      'vitest/no-conditional-in-test': 'error',
      'vitest/no-conditional-tests': 'error',
      'vitest/prefer-each': 'error',
      'vitest/prefer-todo': 'error',
      'vitest/padding-around-describe-blocks': 'error',
      'vitest/padding-around-test-blocks': 'error',
      'vitest/padding-around-expect-groups': 'error',
    },
  },
)
