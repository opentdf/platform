#!/bin/bash
set -euo pipefail

for each in $PULL_NUMBERS; do
	# Get branch info from PR
	branch_name=$(curl -f -s -H "Authorization: token $GH_TOKEN" \
		-H "Accept: application/vnd.github+json" \
		"https://api.github.com/repos/$GITHUB_REPOSITORY/pulls/$each" | jq -r '.head.ref')

	# Use Git to checkout backport branch
	git fetch origin "$branch_name"
	git switch "$branch_name"

	# Get required Git information
	commit_msg=$(git log -1 --format="%B")
	parent_sha=$(git rev-parse HEAD^)
	tree_sha=$(git write-tree)

	# Use API for the commit signing part
	echo "Creating signed commit via API."
	new_commit=$(curl -f -s -X POST \
		-H "Authorization: token $GH_TOKEN" \
		-H "Accept: application/vnd.github+json" \
		-d "{\"message\": $(echo "$commit_msg" | jq -Rs .), \"tree\": \"$tree_sha\", \"parents\": [\"$parent_sha\"]}" \
		"https://api.github.com/repos/$GITHUB_REPOSITORY/git/commits")

	new_commit_sha=$(echo "$new_commit" | jq -r '.sha')

	# Update reference via API
	curl -f -s -X PATCH \
		-H "Authorization: token $GH_TOKEN" \
		-H "Accept: application/vnd.github+json" \
		-d "{\"sha\": \"$new_commit_sha\", \"force\": true}" \
		"https://api.github.com/repos/$GITHUB_REPOSITORY/git/refs/heads/$branch_name"

	echo "Signed commit created for PR #$each on branch $branch_name"
done
