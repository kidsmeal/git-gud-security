# Ultra mode: adversarial multi-agent scan

Ultra mode runs the scan as a `Workflow` so every finding is **refuted before it's reported**.
This is what keeps the false-positive rate near zero on a deep scan: a single LLM pass invents
plausible-but-wrong holes; an adversarial panel that defaults to "false positive" does not.

Use ultra when the user says "ultra," "adversarial," "be exhaustive / thorough / leave nothing,"
or is shipping something where a missed hole is expensive. It costs real tokens. For a quick
sanity check, `full` mode is enough.

## Shape

```
Find        one finder per category in checks.md, each greps+reads the repo and
            returns candidate findings with file:line and a confidence score
   │
Verify      every candidate goes to 3 independent skeptics prompted to REFUTE it
            (default verdict = false positive). Survives only on majority-confirm.
   │
Critique    a completeness critic names attack surfaces/categories not yet covered;
            loop another Find round until two consecutive rounds surface nothing new
   │
Grade       dedup, assign letter grade, write the report + SECURITY_AUDIT.md
```

The adversarial gate matters most for `trace`/`adversarial`-tier holes (IDOR, SSRF, auth
bypass) where "is this actually reachable by an attacker" is the whole question. Pattern-tier
hits (a committed `.env`, an exposed key) rarely need three skeptics, so the verify prompt is
told to confirm those fast and spend its scrutiny on the reachability claims.

## Script

Run this with the `Workflow` tool. Pass `args = { repo, categories }`: `repo` is the absolute repo
path, `categories` is the selection you make **before** launching. Read
`references/ultra-categories.json` (generated from the check library), keep the always-on set
(secrets, authn-authz, injection, cicd, plus the AI/agent categories when the repo shows agent
signals) and add the signal-gated categories whose `appliesTo` matches the repo type. Each entry
carries its `finderDigest`, the trace/adversarial checks that category's finder should hunt. Drop
any entry with an empty `finderDigest`; it's covered by the deterministic scan, no finder needed.

```javascript
export const meta = {
  name: 'gitgud-ultra',
  description: 'Adversarial multi-agent security scan: find per category, refute every finding, loop until dry, grade',
  phases: [
    { title: 'Find', detail: 'one finder per security category, reads the repo' },
    { title: 'Verify', detail: 'three skeptics refute each finding; majority-confirm survives' },
    { title: 'Critique', detail: 'completeness critic + loop until two dry rounds' },
    { title: 'Grade', detail: 'dedup, grade, write report' },
  ],
}

// No Node/process in the Workflow runtime - everything comes from `args`, which the launching
// agent populates (repo path + the category selection with finderDigests).
if (!args || !args.repo) throw new Error('ultra: args.repo (absolute repo path) is required')
const REPO = args.repo
const CATEGORIES = (args.categories || []).filter(c => c.finderDigest && c.finderDigest.length)
if (!CATEGORIES.length) throw new Error('ultra: args.categories needs >=1 entry with a finderDigest')

// Turn a category's finderDigest into the hunt list the finder prompt carries.
const digestText = c => c.finderDigest
  .map(x => `- [${x.severity}] ${x.title} (${x.id}); signals: ${(x.signals || []).join(' | ')}`)
  .join('\n')

const FINDING = {
  type: 'object', additionalProperties: false,
  required: ['id','title','severity','file','line','evidence','why_exploitable','fix','confidence'],
  properties: {
    id: { type: 'string' }, title: { type: 'string' },
    severity: { type: 'string', enum: ['critical','high','medium','low'] },
    file: { type: 'string' }, line: { type: 'number' },
    evidence: { type: 'string', description: 'the exact code/config line that proves it' },
    why_exploitable: { type: 'string', description: 'the concrete attack: who does what to get what' },
    fix: { type: 'string' }, confidence: { type: 'number' },
  },
}
const FINDINGS = { type: 'object', additionalProperties: false, required: ['findings'],
  properties: { findings: { type: 'array', items: FINDING } } }
const VERDICT = { type: 'object', additionalProperties: false, required: ['real','reachable','reason'],
  properties: { real: { type: 'boolean' }, reachable: { type: 'boolean' }, reason: { type: 'string' } } }
const GAPS = { type: 'object', additionalProperties: false, required: ['gaps'],
  properties: { gaps: { type: 'array', items: { type: 'string' } } } }

const seen = new Set()
const key = f => `${f.file}:${f.line}:${f.id}`
const confirmed = []
let dry = 0, round = 0

while (dry < 2 && round < 4) {
  round++
  phase('Find')
  const found = (await parallel(CATEGORIES.map(c => () =>
    agent(
      `Security-audit the repo at ${REPO}. Hunt ONLY for this category's holes:\n${digestText(c)}\n\n` +
      `Use Grep/Read/Bash to find real instances. For each, give file:line, the exact evidence line, ` +
      `and a concrete exploit (who does what). Skip anything in tests/, docs/, *.example, or that is a ` +
      `placeholder. Round ${round}: do not re-report things already found at these locations: ` +
      `${[...seen].join(', ') || '(none yet)'}.`,
      { label: `find:${c.key}`, phase: 'Find', schema: FINDINGS, agentType: 'Explore' })
  ))).filter(Boolean).flatMap(r => r.findings)

  const fresh = found.filter(f => !seen.has(key(f)))
  if (!fresh.length) { dry++; log(`round ${round}: nothing new (dry ${dry}/2)`); continue }
  dry = 0
  fresh.forEach(f => seen.add(key(f)))

  phase('Verify')
  const judged = await parallel(fresh.map(f => () =>
    parallel([0,1,2].map(i => () =>
      agent(
        `You are skeptic #${i+1}. A scanner claims this security hole in ${REPO}:\n` +
        `${f.title} at ${f.file}:${f.line}\nEvidence: ${f.evidence}\nClaimed exploit: ${f.why_exploitable}\n\n` +
        `Try to REFUTE it. Open the file and surrounding code. Default verdict: NOT real, unless you can ` +
        `confirm the vulnerable line exists AND is reachable by an attacker (not dead code, not a test, ` +
        `not gated by an auth check you missed, not a safe public key). Be harsh.`,
        { label: `verify:${f.id}`, phase: 'Verify', schema: VERDICT, agentType: 'Explore' })
    )).then(votes => {
      const v = votes.filter(Boolean)
      const ok = v.filter(x => x.real && x.reachable).length >= 2
      return ok ? { ...f, verdict: v } : null
    })
  ))
  confirmed.push(...judged.filter(Boolean))

  phase('Critique')
  const critic = await agent(
    `Repo: ${REPO}. Confirmed findings so far:\n${JSON.stringify(confirmed.map(f => f.title))}\n\n` +
    `What attack surface or category did we NOT examine? Name concrete unchecked areas (a route file, ` +
    `an upload handler, a webhook, an admin panel, a deserialization point). Empty list if coverage is complete.`,
    { label: `critic:r${round}`, phase: 'Critique', schema: GAPS, agentType: 'Explore' })
  if (critic.gaps.length) log(`round ${round}: critic flagged ${critic.gaps.length} gaps to sweep next round`)
}

phase('Grade')
return { confirmed, rounds: round }
```

After the workflow returns `confirmed`, dedup overlapping findings (same file:line reported under
two ids → keep the highest severity), grade per the rubric in SKILL.md, and write the report in
the standard format to chat and to `SECURITY_AUDIT.md`. Note in the footer that this was an ultra
scan and how many rounds ran, so the coverage claim is honest.

## Notes

- Finders use the `Explore` agent type (read-only: Grep/Read/Glob/Bash) so they can't modify the
  target repo. Verifiers too. Nothing in ultra mode writes to the scanned repo except the final
  `SECURITY_AUDIT.md`.
- The `confidence` from a finder is advisory only; the adversarial vote is the real gate.
- Keep `round < 4` as a backstop so a pathological repo can't loop forever. Two dry rounds is the
  normal exit.
- If the repo is small (a single skill, one MCP server), you can drop to one finder over all
  categories and a single verify round; the multi-round loop earns its cost on larger codebases.
