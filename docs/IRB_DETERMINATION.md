# IRB determination: not human-subjects research

**Recorded 2026-10-23.** The reply came by email from the chair of Carroll University's
Institutional Review Board, answering the inquiry Jack Forden sent (summarised under
"What the IRB was told" below; the longer draft is `docs/IRB_INQUIRY_NOTE.md`). Keep the
original email in the PI's university mailbox. This file is a working record, not the
determination itself.

## What was determined

- **Not human-subjects research.** In the chair's words, "if your data is merely website
  content, there are no human subjects to protect, and therefore we would not need to
  review your project." No IRB review is required.
- **Start date.** The PI is "welcome to begin your work at any time".
- **No other filings.** The IRB chair can speak only to human-subjects policy and did not
  know of other groups to inform. The PI has said he is informing Carroll IT.

## What the IRB was told, and how the current design differs

The determination rests on the description the IRB received. The current design differs
from it in the ways below. None of them involves people, so none plausibly changes the
determination. Still, **send the IRB a one-paragraph update before Gate A** so the record
matches what runs. That costs one email, and it keeps a later reader from finding a gap.

| Told to the IRB | Current design (`docs/analysis_plan.md`) |
|---|---|
| ~300 domains from the national registry, including tribal governments | Wisconsin census of 833 domains; MN, IL, MI and IA optional as a comparison; **tribal nations excluded** |
| At most twice per day | Once a day for about 14 days, then days 21, 28, 45, 60 and 90 (up to 22 snapshots) |
| One ordinary GET per homepage | Usually one. At most three request phases a day (certificate retry, plain-HTTP fallback), each followed by up to 3 same-site redirect hops: a hard ceiling of 12 |
| (not mentioned) | Archived headers from Common Crawl's public archive, with no traffic to sites |
| User agent points to `https://github.com/JForden/JForden/blob/main/README.md` | The user agent carries `https://github.com/JForden/JForden`. Both show the same profile README; no change needed |

## What still needs IRB action

- **The notification experiment needs its own application.** That is the possible later
  phase that emails the security contacts listed in the registry, with randomized timing.
  The chair's reply is explicit: any activity involving human subjects needs an
  application and formal approval first. Doing anything before approval, including
  recruitment, interventions or analysis, is non-compliance. Contacting people and
  measuring their response is the kind of activity that reply covers. **Do not use the
  `security_contact` column, or contact anyone, until that application is approved.**
  Plan for the suggested 3–4 week lead time.
- **A survey of municipal staff needs an application too.** This was idea 9 in the
  design notes: asking clerks or IT staff whether they heard about PHP2Shell and what
  they did. It also needs an application before any recruitment.

## Effect on Gate A

The third precondition in `scripts/cron.disabled` ("IRB/IT determination received") is
met for the IRB part. Gate A itself is still closed. It opens only when the PI says
"GATE A APPROVED", after the notice page is live at `PROJECT_URL`, the plan is frozen,
and Carroll IT has been informed.
