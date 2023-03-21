module.exports = {
  env: {
    es2021: true
  },
  extends: [
    'digitalbazaar',
    'digitalbazaar/import',
    'digitalbazaar/jsdoc',
    'digitalbazaar/module'
  ],
  overrides: [
  ],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module'
  },

  rules: {}
};
