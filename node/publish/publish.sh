set -euo pipefail
PROPOSAL_KIND=${PROPOSAL_KIND:-legacy}
REFRESH_ONLY=${REFRESH_ONLY:-false}
case "$PROPOSAL_KIND" in
  legacy) ;;
  security) PR_BRANCH=maintenance/node-security ;;
  upgrades) PR_BRANCH=maintenance/node-upgrades ;;
  *) echo '::error::Unknown proposal kind'; exit 1 ;;
esac
current_base() {
  if [ "$PROPOSAL_KIND" != legacy ]; then
    git fetch --no-tags origin "$BASE_BRANCH:refs/remotes/origin/$BASE_BRANCH"
    if [ "$(git rev-parse "refs/remotes/origin/$BASE_BRANCH")" != "$AUDIT_SHA" ]; then
      echo '::error::Default branch advanced; discard this stale result and run again.' >&2
      return 1
    fi
  fi
}
still_open() {
  local state
  state=$(gh pr view "$pr_number" --json state --jq .state) || {
    echo '::error::Unable to verify proposal state; refusing publication.' >&2
    exit 1
  }
  case "$state" in
    OPEN) return 0 ;;
    CLOSED|MERGED) return 1 ;;
    *) echo '::error::Unrecognized proposal state; refusing publication.' >&2; exit 1 ;;
  esac
}
validation_status() {
  if [ "$VALIDATION_PASSED" != true ]; then
    echo '::error::Candidate frozen installation or project checks failed; see the retained audit report.'
    return 1
  fi
}
report_content() {
  # Run timestamps and the workflow link change even for the same result.
  sed -E '/^Run: [0-9]{4}-[0-9]{2}-[0-9]{2}T/d; /^\[Workflow run\]\(/d; /^[[:space:]]*$/d' "$1"
}
proposal_title() {
  if [ -n "${NODE_UPDATE_VERSION:-}" ]; then
    printf 'Node: runtime security update to %s\n' "$NODE_UPDATE_VERSION"
    return
  fi
  local summary updates update_word fixes fix_word
  local routine_pattern='^\*\*([0-9]+) routine dependency (update|updates) · Validation '
  local update_pattern='^\*\*([0-9]+) dependency (update|updates) · '
  local fix_pattern=' · ([0-9]+) security (fix|fixes) · '
  local package_fix_pattern=' · ([0-9]+) package security (fix|fixes) · '
  local dependency_pattern='([0-9]+) (routine )?dependency (update|updates)'
  summary=$(head -n 1 "$1")
  if [[ "$summary" == *"platform security update"* ]]; then
    updates=0
    update_word=updates
    if [[ "$summary" =~ $dependency_pattern ]]; then
      updates=${BASH_REMATCH[1]}
      update_word=${BASH_REMATCH[3]}
      if [ -n "${BASH_REMATCH[2]}" ]; then
        printf 'Node: %s routine dependency %s, no security fixes\n' "$updates" "$update_word"
        return
      fi
    fi
    if [[ "$summary" =~ $package_fix_pattern ]]; then
      fixes=${BASH_REMATCH[1]}
      fix_word=${BASH_REMATCH[2]}
      if [ "$fixes" = 0 ]; then
        printf 'Node: %s dependency %s, no security fixes\n' "$updates" "$update_word"
      else
        printf 'Node: %s dependency %s, %s security %s\n' "$updates" "$update_word" "$fixes" "$fix_word"
      fi
    else
      printf 'Node: %s dependency %s, security fixes unconfirmed\n' "$updates" "$update_word"
    fi
    return
  fi
  if [[ "$summary" =~ $routine_pattern ]]; then
    printf 'Node: %s routine dependency %s, no security fixes\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
  elif [[ "$summary" =~ $update_pattern ]]; then
    updates=${BASH_REMATCH[1]}
    update_word=${BASH_REMATCH[2]}
    if [[ "$summary" =~ $fix_pattern ]]; then
      fixes=${BASH_REMATCH[1]}
      fix_word=${BASH_REMATCH[2]}
      if [ "$fixes" = 0 ]; then
        printf 'Node: %s dependency %s, no security fixes\n' "$updates" "$update_word"
      else
        printf 'Node: %s dependency %s, %s security %s\n' "$updates" "$update_word" "$fixes" "$fix_word"
      fi
    else
      printf 'Node: %s dependency %s, security fixes unconfirmed\n' "$updates" "$update_word"
    fi
  else
    printf 'Node: dependency updates, security fixes unconfirmed\n'
  fi
}
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
current_base
expected_head=$(git rev-parse --verify "refs/remotes/origin/$PR_BRANCH" 2>/dev/null || true)
body_file="$RUNNER_TEMP/dependency-audit-pr.md"
pr_title=$(proposal_title "$body_file")
if [ "$PROPOSAL_KIND" != legacy ]; then
  pr_title="${pr_title/Node:/Node $PROPOSAL_KIND:}"
fi
printf '\n%s\n' "$PR_FOOTER" >> "$body_file"
python3 -I - "$body_file" <<'PY'
from pathlib import Path
import sys
length = len(Path(sys.argv[1]).read_text())
if length > 65536:
    raise SystemExit(f"::error::PR body exceeds 65536 characters ({length})")
PY
pr_number=$(gh pr list --state open --head "$PR_BRANCH" --json number,isCrossRepository --jq '[.[] | select(.isCrossRepository == false)][0].number // empty')
if [ "$REFRESH_ONLY" = true ] && { [ -z "${EXPECTED_PR:-}" ] || [ "$pr_number" != "$EXPECTED_PR" ]; }; then
  echo 'The original proposal is no longer open; refresh will not create or replace a PR.'
  exit 0
fi
git checkout -B "$PR_BRANCH"
git add -- "$NPM_PROJECT/package.json"
for file in package-lock.json pnpm-lock.yaml pnpm-workspace.yaml; do
  if [ -f "$NPM_PROJECT/$file" ]; then
    git add -- "$NPM_PROJECT/$file"
  fi
done
if git diff --cached --quiet; then
  if [ "$PROPOSAL_KIND" != legacy ] && [ -n "$pr_number" ] && [ "$VALIDATION_PASSED" = true ] && [ "${PROPOSAL_COMPLETE:-false}" = true ]; then
    current_base
    if still_open; then
      gh pr comment "$pr_number" --body "No dependency changes remain in this channel after auditing and validating the current default branch. Closing this proposal. $PR_FOOTER"
      gh pr close "$pr_number"
    fi
    exit 0
  fi
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
    if git diff --cached --quiet "$expected_head" -- . && { [ "$PROPOSAL_KIND" = legacy ] || git merge-base --is-ancestor "$AUDIT_SHA" "$expected_head"; }; then
      echo 'The open dependency PR already contains this proposal; no dependency push needed. See the current run summary for the audit report.'
      pr_base=$(gh pr view "$pr_number" --json baseRefName --jq .baseRefName)
      existing_body="$RUNNER_TEMP/dependency-audit-existing-pr.md"
      gh pr view "$pr_number" --json body --jq .body > "$existing_body"
      if [ "$VALIDATION_PASSED" != true ] || [ "$pr_base" != "$BASE_BRANCH" ] || ! diff -q <(report_content "$existing_body") <(report_content "$body_file") >/dev/null; then
        current_base
        if [ "$PROPOSAL_KIND" != legacy ] && ! still_open; then exit 0; fi
        gh pr edit "$pr_number" --base "$BASE_BRANCH" --title "$pr_title" --body-file "$body_file"
      else
        existing_title=$(gh pr view "$pr_number" --json title --jq .title)
        if [ "$existing_title" != "$pr_title" ]; then
          current_base
          if [ "$PROPOSAL_KIND" != legacy ] && ! still_open; then exit 0; fi
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
  commit_args=(-m 'Node dependency audit and upgrades')
  if [ -n "${NODE_AUDIT_HISTORY_TRAILERS:-}" ]; then commit_args+=(-m "$NODE_AUDIT_HISTORY_TRAILERS"); fi
  git commit "${commit_args[@]}"
  current_base
  if [ "$PROPOSAL_KIND" != legacy ] && [ -n "$pr_number" ] && ! still_open; then
    echo 'The proposal was closed or merged during the audit; no branch update published.'
    exit 0
  fi
  git push --force-with-lease="refs/heads/$PR_BRANCH:$expected_head" origin "HEAD:refs/heads/$PR_BRANCH"
fi
if [ -n "$pr_number" ]; then
  if [ "$PROPOSAL_KIND" != legacy ] && ! still_open; then exit 0; fi
  gh pr edit "$pr_number" --base "$BASE_BRANCH" --title "$pr_title" --body-file "$body_file"
else
  draft_args=()
  if [ "$VALIDATION_PASSED" != true ]; then
    draft_args=(--draft)
  fi
  gh pr create --head "$PR_BRANCH" --base "$BASE_BRANCH" --title "$pr_title" --body-file "$body_file" "${draft_args[@]}"
fi
validation_status
