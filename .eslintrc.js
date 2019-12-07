module.exports = {
    "env": {
        "commonjs": true,
        "es6": true,
        "node": true
    },
    "extends": "eslint:recommended",
    "globals": {
        "Atomics": "readonly",
        "SharedArrayBuffer": "readonly"
    },
    "parser": "@typescript-eslint/parser",
    "plugins": ["@typescript-eslint"],
    "parserOptions": {
        "ecmaVersion": 2018
    },
    "rules": {
    }
};
