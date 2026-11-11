import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "node_modules"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      ...tseslint.configs.strictTypeChecked,
      ...tseslint.configs.stylisticTypeChecked,
      reactHooks.configs.flat["recommended-latest"],
    ],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Logging is how tokens and customer data leak. The console has no logging; add a
      // scrubbing logger deliberately if one is ever needed.
      "no-console": "error",
      "no-restricted-syntax": [
        "error",
        {
          // Alert text is attacker-controlled. It is rendered only as React text nodes.
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "Render text only. Customer data is attacker-controlled.",
        },
        {
          selector:
            "AssignmentExpression[left.property.name=/^(innerHTML|outerHTML)$/]",
          message: "Do not build HTML from strings.",
        },
        {
          selector: "CallExpression[callee.property.name='insertAdjacentHTML']",
          message: "Do not build HTML from strings.",
        },
        {
          // Tokens stay in memory. Persisting them lets any XSS or shared machine steal a session.
          selector:
            "MemberExpression[object.name=/^(localStorage|sessionStorage)$/], MemberExpression[property.name=/^(localStorage|sessionStorage)$/]",
          message: "Do not use web storage; tokens and customer data stay in memory.",
        },
      ],
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
    },
  },
  {
    files: ["**/*.js"],
    extends: [js.configs.recommended],
  },
);
