package main

// Exact prior V1 binding bytes remain historical decoder inputs.
const historicalRestrictedBinding = `{
  "bindingVersion": "1",
  "platform": "postgres",
  "operations": {
    "history": {"shape": "airbyte", "image": "airbyte/source-postgres:3.8.5@` + testImageDigest + `", "licence": "ELv2"},
    "live": {"shape": "mcp", "server": {"image": "crystaldba/postgres-mcp:0.3.0@` + testImageDigest + `", "args": ["--access-mode=restricted"]}, "tools": ["query"], "probe": {"tool": "query", "failure": "Error:"}, "licence": "MIT"}
  }
}`

// Current synthetic policy fixtures explicitly declare their read and write leaves.
const currentPolicyBinding = `{
  "bindingVersion":"2","platform":"postgres","operations":{
    "history":{"shape":"airbyte","image":"airbyte/source-postgres:3.6.1@` + testImageDigest + `","licence":"ELv2","taxonomy":{"operation":"read","effect":"read-external"}},
    "live":{"shape":"mcp","server":{"image":"ghcr.io/example/mcp-postgres:2.1@` + testImageDigest + `"},"tools":["query","explain"],"toolTaxonomies":{"query":{"operation":"read","effect":"read-external"},"explain":{"operation":"read","effect":"read-external"}},"licence":"MIT"},
    "write":{"shape":"mcp","server":{"image":"ghcr.io/example/mcp-postgres:2.1@` + testImageDigest + `"},"tools":["execute","drop"],"toolTaxonomies":{"execute":{"operation":"act","effect":"act"},"drop":{"operation":"act","effect":"act"}},"licence":"MIT"}
  }
}`
