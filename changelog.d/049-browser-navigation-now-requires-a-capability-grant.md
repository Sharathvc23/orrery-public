### ⚠️ Browser navigation now requires a capability grant

After upgrading, the agent refuses browser navigations until you list the
origins it may open. Write them to `~/.community-member/grants.policy`, one per
line:

```
browser.navigate:https://docs.example.com,https://*.wikipedia.org
```

A refused navigation names the grant it needed and the file to put it in, so the
message carries its own fix. Existing installs will see these refusals from the
first cycle after upgrade; nothing else changes until a grant is written.

The same file also carries `net.http`, `fs.*`, `shell.exec` and `desktop.*`
grants. Those capabilities were already refusing every action — the policy layer
had no reader, so nothing an operator wrote could reach it — and they now
observe what the file says. Writing no file leaves them refusing, as before.
