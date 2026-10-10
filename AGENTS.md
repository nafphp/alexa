# Working on naf/alexa

Read the [shared workflow](https://github.com/nafphp/docs/blob/main/AGENT_WORKFLOW.md)
and [release procedure](https://github.com/nafphp/docs/blob/main/RELEASING.md) before changes.
Use an RC branch, preserve other contributors' work, add regression coverage, commit and
push a review PR. Package code merges and releases belong to the maintainer.

This is a thin Alexa+ integration over `naf/mcp`, `naf/oauth-server`, `naf/database`
and `naf/cli`. Keep protocol, token and migration implementations in their owning plugins.
Host applications register ordinary MCP tools. Personal tools implement `UserToolInterface`
and declare nonempty user scopes; non-user tools require only `mcp:service` or no scopes.
Mixed service/user scope lists fail doctor. OAuth scope-policy errors fail setup before writes.
Application authentication and business permissions remain in the host.

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
On POSIX with PCNTL, run `NAF_SECURITY_HTTP_WORKERS=4 composer test` for real parallel
HTTP refresh/revocation coverage. CI enables this mode; test barriers prove distinct workers
overlap, and teardown terminates their entire isolated process group.

Unreleased user documentation belongs in `nafphp/docs/drafts/`, outside the published site.
