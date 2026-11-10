#!/usr/bin/env bash
# Toolchain check (T4). Runs AS THE AGENT USER inside the sandbox, from a copy
# of the repository. Tools were installed beforehand by install-tools.sh.
set -euo pipefail

echo "== Node $(node --version)"
npm test

echo "== .NET SDK $(dotnet --version)"
dotnet run --project toolchain/dotnet/ArithCheck/ArithCheck.csproj

echo "== $(postgres --version)"
pg_prove -d toolchain_check toolchain/sql/arith_test.sql

echo "toolchain-check: all suites passed"
