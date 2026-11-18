const rules = [
  require('markdownlint-rule-enhanced-proper-names/src/enhanced-proper-names.js'),
  require('markdownlint-rule-no-trailing-slash-in-links/src/no-trailing-slash-in-links.js'),
];

// Legacy rules use null for absent diagnostics; markdownlint 0.42 accepts undefined.
module.exports = rules.map(rule => ({
  ...rule,
  function: (params, onError) => rule.function(params, error => onError({
    ...error, detail: error.detail ?? undefined, context: error.context ?? undefined,
  })),
}));
