package mcp

// nonBlocking is nothing here: Windows opens a named pipe by another name
// space, and a file path never blocks its open.
const nonBlocking = 0
