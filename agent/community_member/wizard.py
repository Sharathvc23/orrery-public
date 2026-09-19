"""
Onboarding Wizard — from nothing to an agent your customers can resolve.

Orrery is a product for SMBs and individuals, and this wizard establishes the
chain that makes one discoverable:

    identity (did:key + keystore + recovery phrase)
        → agent card (AgentFacts, served from this machine)
        → CONSENT (the OWNER authorises the listing)
        → discoverable

⚠️ It used to be a COMMUNITY-DIRECTORY onboarding — "what do you know?", pick
your interests from a list — so that PEERS could find you. That is the wrong
product. A barber has no interests to declare; they have services, and they need
CUSTOMERS to resolve them. The field that carried "interests" is now offerings;
the identifiers behind it are deliberately unchanged (see ``profile.py`` — that
key is inside SIGNED canonical JSON, it is a Postgres column carried verbatim by
the mesh migration, and ``server/embeddings.py`` embeds its literal label into
stored similarity vectors, so renaming it would silently degrade matching
between old and new rows). New vocabulary, same wire.

Three owner paths, and they are NOT equally ready. This is stated here because
the honest version matters more than the symmetrical one:

  INDIVIDUAL — real. Sign in with Google or Microsoft (loopback + PKCE, no client
    secret), which establishes an owner principal that is a DIFFERENT KEY from
    this agent's did:key and is anchored to the IdP's immutable subject id. See
    ``owner.py`` for why the separation is the whole point and what it does and
    does not buy.

  BUSINESS WITH A DOMAIN — real. An ACME-style HTTP-01 or DNS-01 challenge whose
    published value is BOUND TO THE OWNER KEY, so it proves the domain's
    controller authorised this key rather than merely that somebody controls the
    domain. ⚠️ Scope, and the copy must not blur it: this serves businesses that
    OWN A DOMAIN, not businesses generally. HTTP-01 needs the ability to host a
    file at a well-known path; DNS-01 needs registrar access. A three-chair
    barber on Instagram and Square has neither, and is not a smaller version of
    this case — it is one this path cannot serve.

  BUSINESS WITHOUT ONE / PLATFORM — REFUSES, and says why. Proving ownership
    otherwise needs an install credential from the platform that runs the
    business (Shopify, Wix, Toast, Square, Booksy). None of that exists in this
    stack and there is no partner account. A consent step that faked success here
    would publish a business listing nobody authorised, on the exact surface
    where that does the most damage — and quietly routing that business to the
    INDIVIDUAL path would be the same lie by another route, because a personal
    sign-in proves a person and never business ownership.

Paths:
  1. New → identity, agent card, owner consent, LLM, org (optional), start
  2. Returning → load config, show status, start
  3. Moving orgs → import agent, join new org, start
"""

import json
from pathlib import Path

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt

from community_member import llm_runtime as _llm_runtime

from .a2a_client import A2AClient
from .config import Config

console = Console()


def _generate_identity_with_recovery(config: Config) -> str | None:
    """Mint the sovereign identity FROM a fresh BIP39 recovery phrase, so the
    24-word phrase can actually restore it — ``recovery.recover_from_mnemonic``
    re-derives the same Ed25519 keypair deterministically.

    Returns the phrase (to display exactly once), or ``None`` if the recovery
    lib is unavailable — in which case it falls back to a random keypair, which
    is NOT restorable, and the caller warns the user.
    """
    try:
        from . import recovery

        material = recovery.generate_recovery()
    except (ImportError, RuntimeError):
        config.ensure_keypair()  # random fallback — not phrase-restorable
        return None
    config.private_key = material.private_key_b64
    config.public_key = material.public_key_b64
    return material.mnemonic


def _agent_id_from_name(name: str) -> str:
    """Derive the local agent handle from a display name.

    Lowercase, strip spaces/hyphens, cap at 20 chars — the same rule the
    interactive wizard uses, factored out so the headless EXPRESS path mints
    identical handles. Falls back to ``agent`` if the name has no usable
    characters (so a headless provision can never produce an empty handle).
    """
    handle = name.lower().replace(" ", "").replace("-", "")[:20]
    return handle or "agent"


# Local, no-API-key provider used for headless / EXPRESS provisioning. Ollama's
# OpenAI-compatible endpoint needs no key, so the agent stands up fully
# configured without any secret material. Mirrors the local entry in PROVIDERS.
EXPRESS_PROVIDER_ID = "ollama"
EXPRESS_MODEL = "llama3.2"


def express_setup(name: str) -> tuple[Config, str | None]:
    """Non-interactive onboarding — stand up a working, keyless sovereign
    identity with ZERO prompts, for headless provisioning (no TTY).

    Mints the Ed25519 identity from a fresh BIP39 recovery phrase (the same
    path as the interactive wizard, so it stays phrase-restorable), defaults
    the LLM to a LOCAL no-key provider (Ollama) so no API key is required,
    persists config + initial agent state, and returns ``(config, phrase)``.
    It does NOT contact any org and does NOT start the server — a separate run
    serves the agent.

    Idempotent: re-running against an already-configured home loads and returns
    the existing identity untouched, with ``phrase=None`` (nothing fresh minted).

    ``phrase`` is the freshly generated recovery phrase (to surface exactly
    once), or ``None`` when the identity already existed or the recovery lib is
    unavailable and a non-restorable random key was used instead.

    ⚠️ ESTABLISHES NO OWNER PRINCIPAL, so the agent it provisions is NOT
    discoverable — there is no browser and no human to consent, and the announce
    gate refuses without a grant. That is the correct fail-closed outcome:
    headless provisioning must not be a back door that publishes someone who was
    never asked. Consent can be added later from the wizard's Settings.
    """
    from .auth import init_keys

    config = Config.load()
    if config.is_configured():
        return config, None

    recovery_phrase = _generate_identity_with_recovery(config)
    init_keys(config.private_key, config.public_key)

    config.agent_id = _agent_id_from_name(name)
    config.name = name
    config.description = "Community member"
    config.chapter_url = ""  # standalone — join an org later
    config.provider = EXPRESS_PROVIDER_ID
    config.api_key = "local"  # OpenAI client requires a non-empty string; no secret
    config.model = EXPRESS_MODEL
    config.save()

    config.save_agent_state(
        {
            "agent_id": config.agent_id,
            "name": f"@{config.agent_id}",
            "description": config.description,
            "skills": [],
            "interests": [],
            "profile_type": "member",
            "reputation": {"introductions": 0, "sprints": 0, "votes": 0, "events": 0, "contributions": 0},
        }
    )
    return config, recovery_phrase


def _show_recovery_phrase(phrase: str) -> None:
    """Display the recovery phrase exactly once, prominently, and have the user
    acknowledge it. Never logged or written to disk — only the derived keypair
    is persisted (recovery.generate_recovery contract)."""
    words = phrase.split()
    numbered = "   ".join(f"[dim]{i:>2}[/dim] {w}" for i, w in enumerate(words, 1))
    console.print(
        Panel(
            f"{numbered}\n\n"
            "[yellow]Write these words down and keep them offline.[/yellow] They are the "
            "[bold]only[/bold] way\nto restore this identity if you lose this machine — "
            "shown once, never saved to disk.",
            title="🔑 Your recovery phrase",
            border_style="red",
        )
    )
    Confirm.ask("  I have written down my recovery phrase", default=True)


def run_wizard():
    """Main wizard entry point."""
    console.print(
        Panel(
            "[bold]Welcome to your Orrery agent[/bold]\n"
            "[dim]An agent your customers can find and book — one you own outright[/dim]",
            border_style="bright_blue",
        )
    )

    config = Config.load()

    if config.is_configured():
        return returning_member(config)
    else:
        return new_or_import(config)


def new_or_import(config: Config):
    """First-time user — set up fresh, or bring an existing agent."""
    console.print()
    choice = IntPrompt.ask(
        "  Are you...\n"
        "  [1] Setting up for the first time\n"
        "  [2] Returning — I have a backup file\n"
        "  [3] Moving from another org\n\n"
        "  Choose",
        choices=["1", "2", "3"],
        default=1,
    )

    if choice == 1:
        return new_member_flow(config)
    elif choice == 2:
        return import_from_file(config)
    else:
        return move_org(config)


# profile_type values, written into the AGENT-LOCAL agent state (agent.json).
#
# ⚠️ "business" IS NOT A LEGAL VALUE OF THE ORG SERVER'S agents.profile_type
# COLUMN. That column's CHECK constraint permits exactly seven values — member,
# founder, developer, investor, mentor, researcher, leader (infra/init.sql,
# `agents_profile_type_check`) — all of them individual community roles, and it
# is where the org describes what KIND of member someone is, not whether they
# are a person at all. Nothing transmits this value either: register_member's
# payload carries no profile_type and the server hardcodes "member".
#
# So this distinction currently lives only on the machine that made it. Do not
# add profile_type to the registration payload without first widening that CHECK
# constraint — an agent typed "business" would violate it. The individual /
# organisation discriminator arguably belongs in its own field rather than
# borrowed from a role column whose legal values this side does not control;
# that is a schema decision on a table the mesh migration carries verbatim, so
# it is flagged here rather than taken.
PROFILE_TYPE_INDIVIDUAL = "member"
PROFILE_TYPE_BUSINESS = "business"


def choose_owner_kind() -> str:
    """Individual or business. This decides which owner path can be established."""
    console.print("  [dim]This decides how we establish who OWNS this agent —[/dim]")
    console.print("  [dim]which is what lets it be listed publicly at all.[/dim]\n")
    choice = IntPrompt.ask(
        "  [1] Myself — an individual or sole trader\n  [2] A business I own\n\n  Choose",
        choices=["1", "2"],
        default=1,
    )
    return PROFILE_TYPE_INDIVIDUAL if choice == 1 else PROFILE_TYPE_BUSINESS


def collect_offerings(profile_type: str) -> tuple[list[str], list[str]]:
    """What a customer can get, and how it's delivered.

    Returns ``(offerings, capabilities)``. ``offerings`` is what someone can
    actually book or buy — the thing discovery has to match against. It is
    persisted in the field that used to hold "interests"; the identifier is
        unchanged on purpose (see the module docstring).
    """
    is_business = profile_type == PROFILE_TYPE_BUSINESS
    subject = "your business" if is_business else "you"
    example = "haircut, beard trim, kids cut" if is_business else "logo design, consultation, tutoring"

    console.print(f"  [dim]What can a customer get from {subject}? This is what they search for.[/dim]")
    offerings_raw = Prompt.ask(f"  Services or products (comma-separated, e.g. {example})", default="")
    offerings = [s.strip() for s in offerings_raw.split(",") if s.strip()]
    if not offerings:
        console.print("  [yellow]No services listed — customers will have nothing to match against.[/yellow]")

    console.print("\n  [dim]Optional: how the work gets done (tools, languages, specialities).[/dim]")
    capabilities_raw = Prompt.ask("  Capabilities (comma-separated)", default="")
    capabilities = [s.strip() for s in capabilities_raw.split(",") if s.strip()]

    if not is_business and Confirm.ask("  Import capabilities from GitHub?", default=False):
        github_user = Prompt.ask("  GitHub username")
        gh = fetch_github_skills(github_user)
        if gh:
            capabilities = sorted(set(capabilities + gh))
            console.print(f"  [green]✓ Added {len(gh)} capabilities from GitHub[/green]")

    return offerings, capabilities


def new_member_flow(config: Config):
    """Full onboarding: identity → agent card → owner consent → discoverable."""
    console.print("\n[bold]Step 1 of 7: Who is this agent for?[/bold]")
    profile_type = choose_owner_kind()
    is_business = profile_type == PROFILE_TYPE_BUSINESS

    console.print(f"\n[bold]Step 2 of 7: About {'your business' if is_business else 'you'}[/bold]")
    name = Prompt.ask("  Business name" if is_business else "  Your name")
    description = Prompt.ask(
        "  One line a customer would understand",
        default="Local business" if is_business else "Independent",
    )

    console.print("\n[bold]Step 3 of 7: What you offer[/bold]")
    offerings, capabilities = collect_offerings(profile_type)

    # Generate agent ID from name
    agent_id = _agent_id_from_name(name)

    # ── chain link 1: IDENTITY. Minted before consent, because the consent grant
    # names this agent's did:key as its grantee — there is nothing to authorise
    # until the identity exists.
    console.print("\n[bold]Step 4 of 7: Your identity[/bold]")
    console.print("  [dim]An Ed25519 keypair only you hold. It signs your agent card and receipts.[/dim]")
    from .auth import init_keys

    recovery_phrase = _generate_identity_with_recovery(config)
    init_keys(config.private_key, config.public_key)
    console.print("  [green]✓ Cryptographic identity generated[/green]")
    if recovery_phrase:
        _show_recovery_phrase(recovery_phrase)
    else:
        console.print(
            "  [yellow]⚠ Recovery phrase unavailable — the `mnemonic` package is missing, "
            "so this install is incomplete (pip install -e . from agent/). "
            "This identity is NOT restorable if you lose this machine.[/yellow]"
        )

    # Save config early so the consent step (and anything after a crash) has a
    # persisted identity to work from.
    config.agent_id = agent_id
    config.name = name
    config.description = description
    config.skills = capabilities
    # The field that used to hold "interests" now holds offerings. Identifier
    # unchanged deliberately — see the module docstring.
    config.interests = offerings
    config.linkedin_url = ""
    config.save()

    # ── chain links 2-4: the card is served from this machine, CONSENT
    # authorises the listing, and only then is the agent discoverable.
    console.print("\n[bold]Step 5 of 7: Your agent card, and who authorises listing it[/bold]")
    consented = establish_owner_consent(config, profile_type)

    console.print("\n[bold]Step 6 of 7: Power your agent[/bold]")
    provider, api_key, model = configure_llm()

    console.print("\n[bold]Step 7 of 7: Connect to an org[/bold] [dim](optional)[/dim]")
    chapter_url = choose_org()  # "" = run standalone

    skills = capabilities
    interests = offerings
    config.chapter_url = chapter_url
    config.provider = provider
    config.api_key = api_key
    config.model = model
    config.save()

    # Register with the org (signed request + public key for TOFU) — only when
    # the user gave one. Standalone agents skip this. A failed/unreachable org
    # is a warning, never a crash: the agent still runs, and re-running the
    # wizard (or Settings → switch org) registers later.
    if chapter_url:
        console.print("\n  Registering with your org (signed)...")
        try:
            client = A2AClient(
                chapter_url, agent_id=agent_id, private_key=config.private_key, public_key=config.public_key
            )
            result = client.register_member(
                agent_id=agent_id,
                name=f"@{agent_id}",
                description=description,
                skills=skills,
                public_key=config.public_key,
            )
            if result.get("registered"):
                console.print(f"  [green]✓ Registered as @{agent_id}[/green]")
            else:
                console.print(f"  [yellow]Registration: {result.get('error', 'unknown')}[/yellow]")
        except Exception as e:
            console.print(
                f"  [yellow]Couldn't reach the org ({type(e).__name__}) — "
                f"running anyway; it'll register when reachable.[/yellow]"
            )
    else:
        console.print("\n  [dim]Running standalone — no org. Join one later from Settings.[/dim]")

    # Export initial agent state
    config.save_agent_state(
        {
            "agent_id": agent_id,
            "name": f"@{agent_id}",
            "description": description,
            "skills": skills,
            # Offerings, in the field that used to be "interests".
            "interests": interests,
            "profile_type": profile_type,
            "reputation": {"introductions": 0, "sprints": 0, "votes": 0, "events": 0, "contributions": 0},
        }
    )

    show_ready(config, consented=consented)
    return config


def _show_owner_recovery_phrase(phrase: str) -> None:
    """The OWNER phrase, shown once and never stored.

    Distinct from the agent's phrase on purpose: this key is not persisted
    anywhere, so this display is the only copy that will ever exist. The wizard
    says so plainly rather than implying the usual "we keep an encrypted copy".
    """
    words = phrase.split()
    numbered = "   ".join(f"[dim]{i:>2}[/dim] {w}" for i, w in enumerate(words, 1))
    console.print(
        Panel(
            f"{numbered}\n\n"
            "[yellow]This is your OWNER phrase — different from your agent's.[/yellow]\n"
            "Unlike the agent key, this one is [bold]never stored on this machine at all[/bold].\n"
            "You need it only to change or renew your consent later. Withdrawing\n"
            "consent does not need it.",
            title="🔐 Your owner recovery phrase",
            border_style="red",
        )
    )
    Confirm.ask("  I have written down my owner phrase", default=True)


def establish_domain_owner_consent(config: Config, agent_did: str) -> bool:
    """Prove control of a business domain, and record its consent to a listing.

    Same owner key, same DAT, same listing gate as the OIDC path — only the
    evidence type and the anchor differ. The anchor is the DOMAIN, which is
    already durable, so unlike the OIDC path there is no split between a mutable
    locator and an immutable id.

    ⚠️ Nothing is published by this function. The wizard prints what the owner
    must serve and waits for them to say they have done it; the challenge value
    is bound to the owner key, so publishing it proves that key authorised the
    listing rather than merely that somebody controls the domain.
    """
    from . import owner

    try:
        domain = owner.validate_domain(Prompt.ask("\n  Your business domain (e.g. moonbakery.com)"))
    except owner.OwnerConfigError as e:
        console.print(f"  [yellow]⚠ {e}[/yellow]")
        return False

    method_choice = IntPrompt.ask(
        "\n  How would you like to prove it?\n"
        "    [1] Host a file on your website (HTTP-01)\n"
        "    [2] Add a DNS TXT record (DNS-01)\n"
        "    [3] Cancel\n\n  Choose",
        choices=["1", "2", "3"],
        default=1,
    )
    if method_choice == 3:
        return False
    method = owner.HTTP_01 if method_choice == 1 else owner.DNS_01

    owner_identity = owner.mint_owner_identity()
    _show_owner_recovery_phrase(owner_identity.mnemonic)

    challenge = owner.build_domain_challenge(domain, method, owner_identity.did)
    if method == owner.HTTP_01:
        console.print(
            Panel(
                f"Serve this exact text at:\n\n  [bold]{challenge.location}[/bold]\n\n"
                f"with this as the entire body:\n\n  [bold]{challenge.key_authorization}[/bold]\n\n"
                "[dim]It must be reachable over HTTPS and must not redirect.[/dim]",
                title="Publish this to prove you own the domain",
                border_style="cyan",
            )
        )
    else:
        console.print(
            Panel(
                f"Add this TXT record:\n\n  name:  [bold]{owner.dns_challenge_name(domain)}[/bold]\n"
                f"  value: [bold]{challenge.key_authorization}[/bold]\n\n"
                "[dim]DNS changes can take a few minutes to propagate.[/dim]",
                title="Publish this to prove you own the domain",
                border_style="cyan",
            )
        )
    console.print(
        "  [dim]This value is tied to your owner key. Someone copying it from your"
        "\n  public site cannot use it to claim your domain — it will not match theirs.[/dim]"
    )

    if not Confirm.ask("\n  I have published it — check now", default=True):
        return False

    try:
        dns_txt = owner.dnspython_txt_lookup() if method == owner.DNS_01 else None
    except owner.OwnerConfigError as e:
        console.print(f"  [yellow]⚠ {e}[/yellow]")
        return False

    try:
        assertion = owner.verify_domain_challenge(
            challenge, owner_identity.did, http_get_text=owner.httpx_text_fetcher(), dns_txt=dns_txt
        )
    except Exception as e:  # noqa: BLE001 — anything short of proven is not proven
        console.print(f"  [yellow]⚠ {e}[/yellow]")
        console.print("  [dim]Staying private. Nothing has been published to any registry.[/dim]")
        return False

    try:
        evidence = owner.build_domain_evidence(owner=owner_identity, assertion=assertion)
        grant = owner.build_listing_grant(owner=owner_identity, agent_did=agent_did)
    except Exception as e:  # noqa: BLE001 — includes the self-grant refusal
        console.print(f"  [yellow]⚠ Could not record consent ({type(e).__name__}: {e})[/yellow]")
        return False

    owner.save_binding(
        config.home,
        owner_did=owner_identity.did,
        subject=assertion.domain,
        anchor=assertion.anchor,
        evidence=evidence,
        grant=grant,
    )
    console.print(f"\n  [green]✓ Domain verified — {assertion.domain} ({assertion.method})[/green]")
    console.print(f"  [dim]owner key: {owner_identity.did[:34]}…[/dim]")
    console.print(f"  [dim]agent key: {agent_did[:34]}…  (different keys — that is the point)[/dim]")
    console.print("  [green]✓ Consent recorded — your business may now be listed publicly.[/green]")
    return True


def establish_owner_consent(config: Config, profile_type: str) -> bool:
    """Establish an owner principal and record its consent to a public listing.

    Returns True only when a real, owner-signed grant was written. Every other
    outcome returns False and the agent stays private — there is no path here
    that reports success without an artifact behind it.

    ⚠️ The owner principal is a DIFFERENT KEY from this agent's did:key. If those
    two were the same key the grant would be self-delegation: it would pass every
    verification check (measured — Orrery's own DAT verifier accepts
    grantor == grantee) while proving nothing about who authorised the listing.
    """
    from . import owner
    from .crypto import build_did_key

    console.print("  Your agent serves its own card at [bold]/.well-known/agent.json[/bold]")
    console.print("  and its AgentFacts at [bold]/agentfacts.json[/bold], signed by the key you just made.")
    console.print(
        "  [dim]Hosting that card on a third-party card host (e.g. host39) is that host's\n"
        "  job — it calls this agent, not the other way round. Nothing here does it for you.[/dim]\n"
    )
    console.print("  To be [bold]discoverable[/bold], an OWNER has to authorise the listing.")
    console.print("  [dim]Your agent cannot authorise itself — that would prove nothing.[/dim]\n")

    if profile_type == PROFILE_TYPE_BUSINESS:
        agent_did = build_did_key(config.public_key) if config.public_key else ""
        if not agent_did:
            console.print(
                "  [yellow]⚠ No did:key for this agent — nothing to grant consent to. Staying private.[/yellow]"
            )
            return False

        # ⚠️ THE SCOPE LINE, STATED BEFORE THE OFFER, NOT AFTER IT. Domain
        # control proves a business owns a DOMAIN. A business without one is not
        # a smaller case of this — it is a case this path cannot serve at all,
        # and saying so up front is the difference between an honest option and
        # a funnel.
        console.print("  We can prove you own this business [bold]if it has its own domain[/bold].")
        console.print(
            "  [dim]You will publish a one-line proof — either a file on your website\n"
            "  (HTTP-01) or a DNS TXT record (DNS-01). Both need access most small\n"
            "  businesses do not have: a barber on Instagram and Square has neither.[/dim]\n"
        )

        if Confirm.ask("  Does your business have its own domain you can publish to?", default=False):
            if establish_domain_owner_consent(config, agent_did):
                return True
            console.print("  [dim]Domain verification did not complete.[/dim]")

        console.print(
            Panel(owner.platform_install_refusal(), title="⚠ The other business route", border_style="yellow")
        )
        console.print(
            "\n  [dim]You can still run the agent, serve its card, and take bookings.[/dim]\n"
            "  [dim]It just will not be published anywhere until a business owner can be proven.[/dim]"
        )
        if not Confirm.ask(
            "\n  List yourself as an INDIVIDUAL instead? (proves a person, NOT that you own the business)",
            default=False,
        ):
            return False
        console.print(
            "  [yellow]Listing as an individual. The listing will not claim business ownership,[/yellow]\n"
            "  [yellow]because signing in with a personal account does not establish it.[/yellow]"
        )

    agent_did = build_did_key(config.public_key) if config.public_key else ""
    if not agent_did:
        console.print("  [yellow]⚠ No did:key for this agent — nothing to grant consent to. Staying private.[/yellow]")
        return False

    console.print("\n  Sign in to prove who you are:")
    for i, provider in enumerate(owner.PROVIDERS, 1):
        console.print(f"    [{i}] {provider.label}")
    console.print(f"    [{len(owner.PROVIDERS) + 1}] Skip — stay private for now")
    pick = IntPrompt.ask("  Choose", default=len(owner.PROVIDERS) + 1)
    if not 1 <= pick <= len(owner.PROVIDERS):
        console.print("  [dim]Staying private. Nothing has been published.[/dim]")
        return False
    provider = owner.PROVIDERS[pick - 1]

    # ⚠️ FAIL CLOSED. Unset and empty are the same error, and neither falls
    # through to a default or to an unauthenticated listing.
    try:
        client_id = owner.oidc_client_id(provider.id)
    except owner.OwnerConfigError as e:
        console.print(f"\n  [yellow]⚠ {e}[/yellow]")
        console.print("  [dim]Staying private. Nothing has been published.[/dim]")
        return False

    owner_identity = owner.mint_owner_identity()
    _show_owner_recovery_phrase(owner_identity.mnemonic)

    console.print(f"\n  Opening {provider.label} in your browser…")
    try:
        assertion = owner.acquire_owner_assertion(provider, client_id, owner_identity.did)
    except Exception as e:  # noqa: BLE001 — any failure here means NOT consented
        console.print(f"  [yellow]⚠ Sign-in did not complete ({type(e).__name__}: {e})[/yellow]")
        console.print("  [dim]Staying private. Nothing has been published.[/dim]")
        return False

    try:
        evidence = owner.build_owner_evidence(
            owner=owner_identity,
            subject=assertion.subject or assertion.anchor["id"],
            anchor=assertion.anchor,
            id_token=assertion.id_token,
            nonce=assertion.nonce,
        )
        grant = owner.build_listing_grant(owner=owner_identity, agent_did=agent_did)
    except Exception as e:  # noqa: BLE001 — includes the self-grant refusal
        console.print(f"  [yellow]⚠ Could not record consent ({type(e).__name__}: {e})[/yellow]")
        console.print("  [dim]Staying private. Nothing has been published.[/dim]")
        return False

    owner.save_binding(
        config.home,
        owner_did=owner_identity.did,
        subject=assertion.subject or assertion.anchor["id"],
        anchor=assertion.anchor,
        evidence=evidence,
        grant=grant,
    )

    console.print(f"\n  [green]✓ Owner established — {assertion.subject or assertion.anchor['id']}[/green]")
    console.print(f"  [dim]owner key: {owner_identity.did[:34]}…[/dim]")
    console.print(f"  [dim]agent key: {agent_did[:34]}…  (different keys — that is the point)[/dim]")
    console.print("  [green]✓ Consent recorded — your agent may now be listed publicly.[/green]")
    return True


def returning_member(config: Config):
    """Returning member — show status and options."""
    # Migration: generate keypair if missing (existing members before crypto was added)
    if not config.has_keypair():
        config.ensure_keypair()
        from .auth import init_keys

        init_keys(config.private_key, config.public_key)
        config.save()
        console.print("  [green]✓ Cryptographic identity generated (upgrade)[/green]")

        # Re-bind the keypair with the org — only if there is one, and never
        # crash the launch if it's unreachable.
        if config.chapter_url:
            try:
                client = A2AClient(
                    config.chapter_url,
                    agent_id=config.agent_id,
                    private_key=config.private_key,
                    public_key=config.public_key,
                )
                client.register_member(
                    agent_id=config.agent_id,
                    name=config.name or f"@{config.agent_id}",
                    description=config.description,
                    skills=config.skills,
                    public_key=config.public_key,
                )
                console.print("  [green]✓ Re-registered with your org (keypair bound)[/green]")
            except Exception as e:
                console.print(
                    f"  [yellow]Org unreachable ({type(e).__name__}) — "
                    f"keypair saved locally, will re-bind later.[/yellow]"
                )
    else:
        from .auth import init_keys

        init_keys(config.private_key, config.public_key)

    agent_state = config.load_agent_state()
    from . import registry

    verdict = registry.consent_verdict(config)
    listing = "[green]listed[/green]" if verdict else f"[yellow]not listed[/yellow] ({verdict.reason})"

    console.print(
        Panel(
            f"[bold]Welcome back @{config.agent_id}![/bold]\n\n"
            f"  Offering: {len(config.interests)} service(s)\n"
            f"  Discoverable: {listing}\n"
            f"  Org: {config.chapter_url or '(standalone)'}\n",
            border_style="green",
        )
    )

    # Headless / container deploys (Railway, Docker, systemd, etc.)
    # have no TTY. Asking IntPrompt.ask there throws "EOF when
    # reading a line" and crashes the whole process. Detect the
    # missing TTY and auto-pick option 1 (Start agent) — the
    # overwhelmingly common case for any non-interactive boot.
    import sys

    if not sys.stdin.isatty():
        console.print("  [green]✓ Headless / no TTY — auto-starting agent (option 1)[/green]")
        return config

    choice = IntPrompt.ask(
        "  [1] Start agent\n"
        "  [2] View my agent card\n"
        "  [3] Switch org\n"
        "  [4] Export agent (backup)\n"
        "  [5] Settings\n\n"
        "  Choose",
        choices=["1", "2", "3", "4", "5"],
        default=1,
    )

    if choice == 1:
        return config  # caller will start the agent
    elif choice == 2:
        show_agent_card(config, agent_state)
        return returning_member(config)
    elif choice == 3:
        return move_org(config)
    elif choice == 4:
        export_agent(config)
        return returning_member(config)
    elif choice == 5:
        settings_menu(config)
        return returning_member(config)

    return config


def choose_org() -> str:
    """Let the user point at an org, or skip and run standalone.

    Returns the org's base URL, or "" to run on your own (you can join an org
    later from the dashboard's Settings). There is no built-in directory of
    public orgs — you run your own org (`docker compose up` → http://localhost:7000)
    or paste a URL someone gave you.
    """
    console.print("\n  An [bold]org[/bold] is a server that hosts a fleet of agents (run one")
    console.print("  with [bold]docker compose up[/bold] → http://localhost:7000, or paste a URL).")
    console.print("  You can also skip this and run your agent on its own.\n")

    choice = IntPrompt.ask(
        "  [1] Run on my own for now (no org)\n  [2] I have an org URL\n\n  Choose",
        choices=["1", "2"],
        default=1,
    )
    if choice == 1:
        return ""

    url = Prompt.ask("  Org URL", default="http://localhost:7000").strip().rstrip("/")
    # Best-effort reachability check — a heads-up, not a hard gate.
    try:
        resp = httpx.get(f"{url}/health", timeout=5.0)
        if resp.status_code == 200:
            console.print("  [green]✓ org is reachable[/green]")
        else:
            console.print(f"  [yellow]org responded {resp.status_code} — continuing anyway[/yellow]")
    except Exception:
        console.print(
            "  [yellow]couldn't reach that org right now — saved anyway; it'll register when it's up[/yellow]"
        )
    return url


# BASE URL AND LOCALITY COME FROM THE REGISTRY. They were duplicated across five
# tables that disagreed; llm_runtime.PROVIDERS is the one left, and this list now
# carries only what is specific to the wizard — the label a human reads and the
# model this onboarding offers.
#
# The MODEL column is still declared here. The agent's offered default and the
# server's resolved default genuinely differ for openai and groq, and
# reconciling them changes what a deployed chapter resolves when it sets no
# LLM_MODEL — a behaviour change, which this unit does not make.
#
# The anthropic slot pinned the dated Claude Sonnet 4 snapshot, which Anthropic
# RETIRED on 2026-06-15 — requests to a retired model fail, so onboarding handed
# every new Anthropic user a dead model. Replaced with Anthropic's own documented
# successor. Kept in lockstep with server.py::_PROVIDER_CATALOGUE; see
# docs/integrations/LLM_MODEL_PINS.md before changing.
# agent/tests/test_model_pins.py enforces both.
_WIZARD_CHOICES = [
    # (id, label, default_model)
    ("xai", "xAI (Grok)", "grok-3-mini"),
    ("openai", "OpenAI (GPT)", "gpt-4o"),
    ("anthropic", "Anthropic (Claude)", "claude-sonnet-4-6"),
    ("groq", "Groq (Llama)", "llama-3.1-70b-versatile"),
    ("ollama", "Ollama (local)", "llama3.2"),
    ("llama_cpp", "llama.cpp (local)", "local-model"),
    ("mlx_lm", "mlx-lm (local, Apple Silicon)", "local-model"),
]

PROVIDERS = [
    # (id, label, base_url, default_model, is_local)
    (pid, label, _llm_runtime.PROVIDERS[pid].base_url, model, _llm_runtime.PROVIDERS[pid].is_local)
    for pid, label, model in _WIZARD_CHOICES
]


def configure_llm() -> tuple[str, str, str]:
    """Configure LLM provider and key.

    Local providers (Ollama / llama.cpp / mlx-lm) skip the key prompt;
    we just verify the endpoint is reachable so the user knows their
    server is up before the agent tries its first inference.
    """
    console.print("  [dim]Pick where your agent's brain runs.[/dim]")
    console.print("  [dim]Local options keep every prompt on your machine.[/dim]\n")
    for i, (_pid, label, base_url, _model, is_local) in enumerate(PROVIDERS, 1):
        tag = "[green]local[/green]" if is_local else "[cyan]cloud[/cyan]"
        console.print(f"  [{i}] {label}  {tag}  [dim]{base_url}[/dim]")

    choice = IntPrompt.ask("  Provider", default=1)
    idx = max(0, min(choice - 1, len(PROVIDERS) - 1))
    provider_id, _, base_url, default_model, is_local = PROVIDERS[idx]

    if is_local:
        # Local server — no key. Verify reachable; offer model name.
        console.print(f"  [dim]Connecting to {base_url}…[/dim]")
        api_key = "local"  # OpenAI client requires a non-empty string
        try:
            client = _llm_runtime.build_client(_llm_runtime.resolve(provider_id))
            models = client.models.list()
            available = [m.id for m in models.data] if hasattr(models, "data") else []
            if available:
                console.print(f"  [green]✓ {len(available)} models available[/green]")
                model = Prompt.ask("  Model name", default=available[0])
            else:
                console.print("  [yellow]⚠ server reachable but no models listed[/yellow]")
                model = Prompt.ask("  Model name", default=default_model)
        except Exception as e:
            console.print(f"  [yellow]⚠ could not reach {base_url} — {type(e).__name__}[/yellow]")
            console.print("  [dim]Hint: start your server (e.g. `ollama serve`) before the agent connects.[/dim]")
            model = Prompt.ask("  Model name", default=default_model)
        return provider_id, api_key, model

    api_key = Prompt.ask("  API Key", password=True)

    # Verify key works
    console.print("  Verifying key...", end="")
    try:
        client = _llm_runtime.build_client(_llm_runtime.resolve(provider_id), api_key=api_key)
        client.models.list()
        console.print(" [green]✓ verified[/green]")
    except Exception:
        console.print(" [yellow]⚠ could not verify (will try anyway)[/yellow]")

    return provider_id, api_key, default_model


def fetch_github_skills(username: str) -> list[str]:
    """Extract skills from GitHub repos."""
    try:
        resp = httpx.get(f"https://api.github.com/users/{username}/repos?sort=pushed&per_page=30", timeout=10.0)
        if resp.status_code != 200:
            return []
        repos = resp.json()
        langs = {}
        for repo in repos:
            lang = repo.get("language")
            if lang:
                langs[lang.lower()] = langs.get(lang.lower(), 0) + 1
        return sorted(langs, key=lambda x: -langs[x])[:8]
    except Exception:
        return []


def show_agent_card(config: Config, agent_state: dict):
    """Display the agent card, including who authorised any public listing."""
    from . import attestation_copy, owner, registry

    capabilities = agent_state.get("skills", [])
    rep = agent_state.get("reputation", {})
    binding = owner.load_binding(config.home)
    verdict = registry.consent_verdict(config)
    if verdict:
        # ⚠️ "authorised by <subject>" WAS WRONG, not merely generic. `subject`
        # is the owner binding's subject — for an OIDC binding, the person's
        # email address — so the line read as the barber having authorised their
        # own listing. The derivation says otherwise: an OIDC binding whose
        # subject is not the business's recorded principal is `operator_vouched`,
        # meaning THE OPERATOR authorised it. The old line named a party that had
        # not made the assertion attributed to them.
        #
        # So the attestation leads, the subject stays as the recorded binding it
        # is, and the caveat says what the check does not establish.
        copy = attestation_copy.rendering_for(owner.owner_attestation(verdict))
        subject = (binding or {}).get("subject") or "(none recorded)"
        listing = (
            f"[green]{copy.label}[/green]\n"
            f"  {copy.sentence}\n"
            f"  [dim]{copy.caveat}[/dim]\n"
            f"  [dim]Owner binding subject: {subject}[/dim]"
        )
    else:
        listing = f"[yellow]not listed[/yellow] ({verdict.reason})"
    console.print(
        Panel(
            f"[bold]@{config.agent_id}[/bold]\n"
            f"{config.description}\n\n"
            f"Offering: {', '.join(config.interests[:10])}\n"
            f"Capabilities: {', '.join(capabilities[:10])}\n"
            f"Listing: {listing}\n"
            f"Reputation: intros={rep.get('introductions', 0)} votes={rep.get('votes', 0)} "
            f"events={rep.get('events', 0)} contributions={rep.get('contributions', 0)}\n"
            f"Org: {config.chapter_url or '(standalone)'}",
            title="Agent Card",
            border_style="cyan",
        )
    )


def export_agent(config: Config):
    """Export agent to a backup file."""
    state = config.load_agent_state()
    path = Path.cwd() / f"{config.agent_id}.agent.json"
    with open(path, "w") as f:
        json.dump(state, f, indent=2)
    console.print(f"  [green]✓ Exported to {path}[/green]")


def import_from_file(config: Config):
    """Import agent from a backup file."""
    path = Prompt.ask("  Path to .agent.json file")
    try:
        with open(path) as f:
            state = json.load(f)
        config.agent_id = state.get("agent_id", "")
        config.name = state.get("name", "")
        config.description = state.get("description", "")
        config.skills = state.get("skills", [])
        config.interests = state.get("interests", [])
        console.print(f"  [green]✓ Loaded @{config.agent_id} — {len(config.skills)} skills[/green]")

        console.print("\n[bold]Join an org:[/bold]")
        config.chapter_url = choose_org()

        console.print("\n[bold]Configure LLM:[/bold]")
        config.provider, config.api_key, config.model = configure_llm()

        config.save()
        config.save_agent_state(state)
        show_ready(config)
        return config
    except Exception as e:
        console.print(f"  [red]Error: {e}[/red]")
        return None


def move_org(config: Config):
    """Move agent to a different org."""
    console.print("\n[bold]Switch Org[/bold]")
    new_url = choose_org()
    if new_url:
        config.chapter_url = new_url
        config.save()

        # Re-register with new server (signed)
        config.ensure_keypair()
        client = A2AClient(
            new_url, agent_id=config.agent_id, private_key=config.private_key, public_key=config.public_key
        )
        result = client.register_member(
            agent_id=config.agent_id,
            name=config.name,
            description=config.description,
            skills=config.skills,
            public_key=config.public_key,
        )
        if result.get("registered"):
            console.print("  [green]✓ Registered with new org[/green]")
        show_ready(config)
    return config


def settings_menu(config: Config):
    """Settings submenu."""
    from . import registry

    console.print("\n[bold]Settings[/bold]")
    listed = bool(registry.consent_verdict(config))
    consent_label = "Withdraw my public listing" if listed else "Authorise a public listing"
    choice = IntPrompt.ask(
        "  [1] Change LLM provider/key\n"
        "  [2] Update what I offer\n"
        "  [3] Update capabilities\n"
        f"  [4] {consent_label}\n"
        "  [5] Back\n\n  Choose",
        default=5,
    )
    if choice == 1:
        config.provider, config.api_key, config.model = configure_llm()
        config.save()
    elif choice == 2:
        offerings_raw = Prompt.ask("  Services or products (comma-separated)", default=", ".join(config.interests))
        config.interests = [s.strip() for s in offerings_raw.split(",") if s.strip()]
        config.save()
    elif choice == 3:
        capabilities_raw = Prompt.ask("  Capabilities (comma-separated)", default=", ".join(config.skills))
        config.skills = [s.strip() for s in capabilities_raw.split(",") if s.strip()]
        config.save()
    elif choice == 4:
        if listed:
            withdraw_listing(config)
        else:
            profile_type = (config.load_agent_state() or {}).get("profile_type") or PROFILE_TYPE_INDIVIDUAL
            establish_owner_consent(config, profile_type)


def withdraw_listing(config: Config) -> bool:
    """Withdraw or pause a public listing.

    ⚠️ Withdrawal RECORDS a revocation; it does not delete the binding. Deleting
    would make the retraction indistinguishable from a subject that never
    existed, so a caller could not tell "this business no longer has an agent"
    from "resolution failed" — the ambiguity this is built to remove.

    Signing is offered, never required. The owner key is not persisted, so
    demanding the phrase would mean someone who lost it could not withdraw their
    own listing — a worse failure than an unattested record. Both outcomes are
    honest about which one they are.
    """
    from . import owner

    console.print("\n  [bold]Withdraw or pause your listing[/bold]")
    console.print(
        "  [dim]Pausing is reversible. Withdrawing is permanent: re-listing later\n"
        "  needs fresh consent, because a caller who saw the withdrawal must not\n"
        "  be made wrong by it quietly coming back.[/dim]\n"
    )
    choice = IntPrompt.ask(
        "  [1] Pause it for now (suspended)\n  [2] Withdraw it permanently (revoked)\n  [3] Cancel\n\n  Choose",
        choices=["1", "2", "3"],
        default=3,
    )
    if choice == 3:
        return False
    state = owner.LIFECYCLE_SUSPENDED if choice == 1 else owner.LIFECYCLE_REVOKED
    if state == owner.LIFECYCLE_REVOKED and not Confirm.ask(
        "  This cannot be undone. Withdraw permanently?", default=False
    ):
        return False

    reason = Prompt.ask("  Reason (optional, shown to anyone who resolves you)", default="") or None

    owner_identity = None
    if Confirm.ask(
        "\n  Sign this with your owner phrase? (proves it was YOU, not just this machine)",
        default=False,
    ):
        phrase = Prompt.ask("  Your 24-word OWNER phrase")
        try:
            owner_identity = owner.recover_owner_identity(phrase)
        except Exception as e:  # noqa: BLE001 — a bad phrase must not block withdrawal
            console.print(f"  [yellow]⚠ Could not read that phrase ({type(e).__name__}) — recording unsigned.[/yellow]")
            owner_identity = None

    try:
        answer = owner.set_lifecycle(config.home, state, reason=reason, owner=owner_identity)
    except owner.LifecycleError as e:
        console.print(f"  [yellow]⚠ {e}[/yellow]")
        return False

    console.print(f"\n  [green]✓ Listing is now {answer.state}[/green] [dim](since {answer.since})[/dim]")
    if answer.attested:
        console.print("  [dim]Owner-signed — anyone resolving you can verify you withdrew it.[/dim]")
    else:
        console.print(
            "  [dim]Recorded unsigned: this agent will not be published, and anyone"
            "\n  resolving it is told so — but that record is this machine's word,"
            "\n  not a proof from your owner key.[/dim]"
        )
    return True


def show_ready(config: Config, *, consented: bool | None = None):
    """Show the agent is ready, and say plainly whether it is discoverable.

    ``consented`` is passed by the paths that just ran the consent step. When
    omitted, the on-disk grant is re-checked rather than assumed, so this can
    never claim a listing that the gate would refuse.
    """
    if consented is None:
        from . import registry

        consented = bool(registry.consent_verdict(config))
    discovery = (
        "[green]yes[/green] — an owner authorised it" if consented else "[yellow]no[/yellow] — no owner consent on file"
    )
    console.print(
        Panel(
            f"[bold green]@{config.agent_id} is ready![/bold green]\n\n"
            # The dashboard URL (with its auto-picked port) is printed by the
            # launcher once the server is actually bound — not here.
            f"  Org: {config.chapter_url or '(standalone)'}\n"
            f"  Offering: {len(config.interests)} service(s) customers can match\n"
            f"  Discoverable: {discovery}\n"
            f"  Privacy: notes + goals stay local\n\n"
            f"  Your agent serves its card and answers on your behalf.\n"
            f"  Nothing is published unless an owner consented to it.",
            border_style="green",
        )
    )
