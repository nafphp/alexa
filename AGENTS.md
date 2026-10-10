# Working on naf/alexa

Read the [shared workflow](https://github.com/nafphp/docs/blob/main/AGENT_WORKFLOW.md)
and [release procedure](https://github.com/nafphp/docs/blob/main/RELEASING.md) before changes.
Use an RC branch, preserve other contributors' work, add regression coverage, commit and
push a review PR. Package code merges and releases belong to the maintainer.

This is a thin Alexa+ integration over `naf/mcp`, `naf/oauth-server`, `naf/database`
and `naf/cli`. Keep protocol, token and migration implementations in their owning plugins.
Host applications register ordinary MCP tools. Personal tools implement `UserToolInterface`
and declare their scopes; application authentication and business permissions remain in the host.

Configuration lives in `src/config.php`. `alexa:setup` registers separate service and
account-linking OAuth clients; never give a service client user scopes. Migrations are opt-in.
Secrets are shown only on creation. `alexa:doctor` performs local checks and cannot certify
Amazon connectivity, consent UX, hosted images or latency. Amazon deployment remains a
separate Alexa AI CLI operation requiring preview access.

Run `composer test`, `composer style:check` and `composer validate --strict`. Test commands
through the real CLI console and HTTP behavior through an installed host. CI installs
published stable dependencies with Composer; manifests must keep stable constraints and
contain no sibling repositories.
PHP 8.3 is the minimum. Follow the shared PER Coding Style 3.0 rules and formatter.

Unreleased user documentation belongs in `nafphp/docs/drafts/`, outside the published site.
