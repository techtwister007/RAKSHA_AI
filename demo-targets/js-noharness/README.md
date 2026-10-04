# js-noharness — a JavaScript target that ships no fuzz harness

`convert(spec)` builds a shell command from the operator's string and runs it with
`child_process.execSync` (shell form): a command injection. No harness, no `package.json`
dependencies (Node built-ins only). RAKSHA discovers `convert`, synthesizes the `jssinkguard`
preload harness, and drives the find→fix→prove loop through the five-check gate — the JavaScript
mirror of the `py-noharness` lane.
