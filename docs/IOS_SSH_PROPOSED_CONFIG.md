# Proposed IOS SSH Configuration — Read-Only Collector Account

> **STATUS: PROPOSAL — FOR MANUAL REVIEW ONLY.**
> Nothing in this document has been applied to any device. It must never be
> pushed remotely by the collector (the collector cannot enter configuration
> mode at all). Apply only after your own review, during an approved
> maintenance window, using your normal out-of-band configuration process.

## 1. Why a dedicated account

The Phase-2 collector authenticates with environment variables
(`NETTWIN_DEVICE_USERNAME` / `NETTWIN_DEVICE_PASSWORD`) and dispatches only
five allowlisted `show` commands from the application side. **The application
allowlist is a client-side safety net, not device-side authorization** — a
compromised or buggy client could still attempt anything the account permits.
Device-side restriction is what actually bounds the blast radius.

## 2. Proposed configuration (IOS 15.2)

```ios
! --- dedicated read-only collector account -----------------------------
username nettwin-ro secret <STRONG-SECRET-HERE>
        privilege 1
        no service-password-encryption   ! (only if your standards require;
                                          !  otherwise leave defaults)

! --- restrict SSH to management sources + harden negotiation -----------
ip ssh time-out 30
ip ssh authentication-retries 3
ip ssh version 2
! Example: restrict SSH to the management network only (adjust to your lab)
access-list 10 permit 172.30.201.0 0.0.0.255
line vty 0 15
 transport input ssh
 access-class 10 in
 login local
 no exec
```

Notes:

* `privilege 1` (default user EXEC) is intentional: the five `show` commands
  are available at level 1 on IOS 15.2, while `configure terminal`,
  `write memory`, `reload`, `clear` and `show running-config` are not.
* The account carries **no enable secret** — the collector never attempts
  enable mode, and the account must not have one it could use.
* `<STRONG-SECRET-HERE>`: choose a unique high-entropy secret; never reuse
  an admin password; never commit it to git/YAML/logs.

## 3. How to verify the account's privilege (operator, on the device or via a manual SSH session)

```ios
show privilege          ! must print: Privilege level: 1
show running-config | include username   ! review the account line
```

From a normal (non-admin) shell you can also confirm what is blocked:

```text
ssh nettwin-ro@<device>
R2-1> enable            ! should ask for a password the account does not have
R2-1> show running-config  ! should be denied at privilege 1
R2-1> configure terminal   ! should be denied at privilege 1
```

The collector itself performs a different, automated check: it verifies that
only allowlisted commands are dispatched (unit tests + pre-connection
rejection). That check complements — and never replaces — the device-side
privilege verification above.

## 4. Verification checklist (fill in during live validation)

- [ ] `show privilege` on the collector account prints `Privilege level: 1`
- [ ] `show running-config` denied for the collector account
- [ ] `configure terminal` denied for the collector account
- [ ] `reload` / `clear ...` denied for the collector account
- [ ] SSH from any source outside the management ACL is refused
- [ ] Collector run with `NETTWIN_DEVICE_USERNAME=nettwin-ro` succeeds for
      the five `show` commands (see UBUNTU_LIVE_TEST_GUIDE.md)
