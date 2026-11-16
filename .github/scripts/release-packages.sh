#!/usr/bin/env bash
set -euo pipefail

# Resolves the crate a `<crate>-v1.2.3` release tag publishes to crates.io and checks
# its manifest version is 1.2.3. Prints `packages=<crate>` for `$GITHUB_OUTPUT`.

TAG="${1:?usage: release-packages.sh <crate>-v<version>}"

if [[ ! "$TAG" =~ ^(.+)-v([0-9]+\.[0-9]+\.[0-9]+.*)$ ]]; then
    echo "error: '${TAG}' is not a release tag like <crate>-v1.2.3" >&2
    exit 1
fi
package="${BASH_REMATCH[1]}"
VERSION="${BASH_REMATCH[2]}"

metadata="$(cargo metadata --format-version 1 --no-deps --locked)"
# `publish` is null when unrestricted, or a list of allowed registries.
publishable="$(jq -r '.packages[] | select(.publish == null or (.publish | index("crates-io"))) | .name' <<<"$metadata")"
if ! grep -qxF -- "$package" <<<"$publishable"; then
    echo "error: tag ${TAG} names ${package}, which is not a publishable crate in this workspace" >&2
    exit 1
fi

actual="$(jq -r --arg name "$package" '.packages[] | select(.name == $name) | .version' <<<"$metadata")"
if [[ "$actual" != "$VERSION" ]]; then
    echo "error: ${package} is ${actual}, but tag ${TAG} releases ${VERSION}" >&2
    exit 1
fi

echo "packages=${package}"
