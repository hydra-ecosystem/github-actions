set -euo pipefail
validation_status() {
  if [ "$VALIDATION_PASSED" != true ]; then
    echo '::error::Candidate frozen installation or production build validation failed; see the retained audit report.'
    return 1
  fi
}
report_content() {
  # Run timestamps and the workflow link change even for the same result.
  sed -E '/^Run: [0-9]{4}-[0-9]{2}-[0-9]{2}T/d; /^\[Workflow run\]\(/d; /^[[:space:]]*$/d' "$1"
}
proposal_title() {
  local summary updates update_word fixes fix_word
  local routine_pattern='^\*\*([0-9]+) routine dependency (update|updates) · Build '
  local update_pattern='^\*\*([0-9]+) dependency (update|updates) · '
  local fix_pattern=' · ([0-9]+) security (fix|fixes) · '
  summary=$(head -n 1 "$1")
  if [[ "$summary" =~ $routine_pattern ]]; then
    printf 'Docusaurus: %s routine dependency %s, no security fixes\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
  elif [[ "$summary" =~ $update_pattern ]]; then
    updates=${BASH_REMATCH[1]}
    update_word=${BASH_REMATCH[2]}
    if [[ "$summary" =~ $fix_pattern ]]; then
      fixes=${BASH_REMATCH[1]}
      fix_word=${BASH_REMATCH[2]}
      if [ "$fixes" = 0 ]; then
        printf 'Docusaurus: %s dependency %s, no security fixes\n' "$updates" "$update_word"
      else
        printf 'Docusaurus: %s dependency %s, %s security %s\n' "$updates" "$update_word" "$fixes" "$fix_word"
      fi
    else
      printf 'Docusaurus: %s dependency %s, security fixes unconfirmed\n' "$updates" "$update_word"
    fi
  else
    printf 'Docusaurus: dependency updates, security fixes unconfirmed\n'
  fi
}
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
expected_head=$(git rev-parse --verify "refs/remotes/origin/$PR_BRANCH" 2>/dev/null || true)
body_file="$RUNNER_TEMP/dependency-audit-pr.md"
pr_title=$(proposal_title "$body_file")
printf '\n%s\n' "$PR_FOOTER" >> "$body_file"
pr_number=$(gh pr list --state open --head "$PR_BRANCH" --json number,isCrossRepository --jq '[.[] | select(.isCrossRepository == false)][0].number // empty')
git checkout -B "$PR_BRANCH"
git add -- "$NPM_PROJECT/package.json"
for file in package-lock.json pnpm-lock.yaml pnpm-workspace.yaml; do
  if [ -f "$NPM_PROJECT/$file" ]; then
    git add -- "$NPM_PROJECT/$file"
  fi
done
if git diff --cached --quiet; then
  echo 'No dependency changes; existing PR branch and report retained. See the Actions run summary for this audit report.'
  validation_status
  exit 0
else
  if [ -n "$pr_number" ] && [ "$VALIDATION_PASSED" != true ]; then
    is_draft=$(gh pr view "$pr_number" --json isDraft --jq .isDraft)
    if [ "$is_draft" != true ]; then
      gh pr ready "$pr_number" --undo
    fi
  fi
  if [ -n "$pr_number" ] && [ -n "$expected_head" ]; then
    if git diff --cached --quiet "$expected_head" -- .; then
      echo 'The open dependency PR already contains this proposal; no dependency push needed. See the current run summary for the audit report.'
      pr_base=$(gh pr view "$pr_number" --json baseRefName --jq .baseRefName)
      existing_body="$RUNNER_TEMP/dependency-audit-existing-pr.md"
      gh pr view "$pr_number" --json body --jq .body > "$existing_body"
      if [ "$VALIDATION_PASSED" != true ] || [ "$pr_base" != "$BASE_BRANCH" ] || ! diff -q <(report_content "$existing_body") <(report_content "$body_file") >/dev/null; then
        gh pr edit "$pr_number" --base "$BASE_BRANCH" --title "$pr_title" --body-file "$body_file"
      else
        existing_title=$(gh pr view "$pr_number" --json title --jq .title)
        if [ "$existing_title" != "$pr_title" ]; then
          gh pr edit "$pr_number" --title "$pr_title"
        fi
      fi
      validation_status
      exit 0
    else
      comparison_status=$?
      if [ "$comparison_status" -ne 1 ]; then
        echo '::error::Unable to compare the existing PR with the candidate; refusing publication.'
        exit "$comparison_status"
      fi
    fi
  fi
  git commit -m 'Documentation dependency audit and upgrades'
  git push --force-with-lease="refs/heads/$PR_BRANCH:$expected_head" origin "HEAD:refs/heads/$PR_BRANCH"
fi
if [ -n "$pr_number" ]; then
  gh pr edit "$pr_number" --base "$BASE_BRANCH" --title "$pr_title" --body-file "$body_file"
else
  draft_args=()
  if [ "$VALIDATION_PASSED" != true ]; then
    draft_args=(--draft)
  fi
  gh pr create --head "$PR_BRANCH" --base "$BASE_BRANCH" --title "$pr_title" --body-file "$body_file" "${draft_args[@]}"
fi
validation_status
