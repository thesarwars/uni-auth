// @ts-check
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'coverage/**', 'scripts/**'] },

  eslint.configs.recommended,

  // Config files are plain JS and outside the TS project: no type-aware linting.
  {
    files: ['*.config.mjs', '*.config.js'],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: { sourceType: 'module' },
  },

  {
    files: ['**/*.ts'],
    extends: [...tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      // NOT enabled: consistent-type-imports. Nest's dependency injection resolves providers
      // from the runtime type metadata that emitDecoratorMetadata writes, and `import type`
      // erases it - a constructor parameter imported as a type cannot be injected.
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      // Nest controllers and lifecycle hooks are legitimately async without awaiting.
      '@typescript-eslint/require-await': 'off',
    },
  },

  // Tests read untyped JSON response bodies; asserting on them is the point.
  {
    files: ['tests/**/*.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
    },
  },
);
