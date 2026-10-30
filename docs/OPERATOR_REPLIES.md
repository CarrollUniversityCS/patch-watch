# Replies to site operators (DRAFTS: nothing here is sent automatically)

**Status: drafts for Jack to send himself, from jforden@carrollu.edu.** The study contacts no one on its own. An
operator who sees the traffic may write to the address in the user agent (`CarrollPHPStudy/1.0`) or in the notice at
https://github.com/JForden/JForden . These templates are for those replies, and for no outgoing message of any other
kind. Do not use the registry's security-contact column, and do not write first to anyone: that would be a
human-subjects activity needing its own IRB application (see `docs/IRB_DETERMINATION.md`).

Placeholders in [brackets] are filled in per message. Keep replies short, plain and free of anything about other sites.

## Handling checklist (every message)

1. **Opt-out or "stop":** add the domain to `blocklist.txt` the same day (the 24-hour promise), note it in
   `logs/optouts.md` (date, domain, who wrote, one line), then send reply 1. The daily check confirms the domain is on
   the blocklist and was not contacted afterwards.
2. **Complaint, abuse report or anything that suggests harm** (an outage, a security incident, a legal or law-enforcement
   contact): stop first. Create `logs/abuse.flag` (one line: what and when), which halts every scheduled run, then send
   reply 3, then tell the department chair. Only Jack clears the flag. Two such messages in a week, or one that
   plausibly links an outage to the study, is a stop-and-review.
3. **A question or a block request:** reply 2 or 4. Never argue, never ask the operator to do anything, never ask what
   software they run.
4. Never confirm or deny any result about a specific site, and never say whether the site "looks vulnerable". The only
   thing said about a site is that it was or was not requested.
5. Forwarded or misdirected mail: reply 5. Press or a hosting provider: reply 6.

## 1. Opt-out confirmation

Subject: Re: [their subject]

Hello,

Thank you for writing. [domain] has been removed from the study as of [date and time]. We will not send it any further
requests. No reason was needed and none will be recorded beyond your request.

If you would like to confirm it from your side, you can also block the user agent `CarrollPHPStudy/1.0`.

Jack Forden
Carroll University, Computer Science
jforden@carrollu.edu

## 2. "What is this traffic?"

Subject: Re: [their subject]

Hello,

The requests you saw come from a Carroll University research study of how quickly government websites install published
security fixes. Each request is one ordinary request for a site's home page ("/"), made at most once a day (at most
three if the first one fails, with a few redirects inside the same site), at most one at a time to the same address,
carrying the user agent `CarrollPHPStudy/1.0`, a link to our notice and this email address. We read at most the first 64
kilobytes of the page and the response headers your server sends, store the headers and not the page, send no cookies and
look at no other path, and we never send an exploit or test for a weakness.

We publish only group totals (nothing under ten, never a site or vendor name). The full description, and how to opt out,
is here: https://github.com/JForden/JForden . If you want to be removed, reply with your domain and it will be done within
24 hours.

Jack Forden
Carroll University, Computer Science
jforden@carrollu.edu

## 3. Complaint or abuse-report acknowledgement

Subject: Re: [their subject]

Hello,

Thank you for telling us. We have stopped all requests to [domain], and, while we look into what you describe, the study
is paused. We will not resume requests to your site without your agreement. Please tell us the time (with time zone) and
the address you saw, so we can compare it with our own request log.

I am the researcher responsible and will write again by [date, no later than the next business day].

Jack Forden
Carroll University, Computer Science
jforden@carrollu.edu

## 4. Firewall or WAF courtesy (a site that refuses us, or an operator who asks how to block)

Subject: Re: [their subject]

Hello,

A site that refuses our request is recorded as "not measured", never as anything about its security, and it is not asked
again that day. If you prefer to refuse us by policy, blocking the user agent `CarrollPHPStudy/1.0` is fully respected; no
reply is needed. If you want [domain] taken off the list entirely, say so and it will be removed within 24 hours.

Jack Forden
Carroll University, Computer Science
jforden@carrollu.edu

## 5. Wrong recipient or forwarded message

Subject: Re: [their subject]

Hello,

I think this reached me by forwarding. The study is a Carroll University measurement of how quickly government websites
install published fixes; the notice is at https://github.com/JForden/JForden . If this concerns a particular domain, reply
with its name and I will remove it from the study within 24 hours, or point me to the right person.

Jack Forden
jforden@carrollu.edu

## 6. A journalist or a hosting provider

Subject: Re: [their subject]

Hello,

Thank you for asking. The project and its limits are described at https://github.com/JForden/JForden . We publish only
group totals; we do not name or rank individual sites, hosting providers or vendors, and we do not share per-site results
with anyone. I am happy to answer questions about the method. I will not discuss results for any individual site.

Jack Forden
Carroll University, Computer Science
jforden@carrollu.edu
