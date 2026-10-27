"""Presentation and route selection only. Canonical IDs remain the authority."""
import hashlib
import json
import re
from .core import AGENTS, BridgeError

METADATA = ("display_name", "platform", "role", "aliases")
ALIAS = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")


def validate_metadata(entry):
    for key in ("display_name", "platform", "role"):
        if key in entry:
            value = entry[key]
            if (not isinstance(value, str) or not 1 <= len(value) <= 64
                    or value != value.strip() or "/" in value
                    or not value.isprintable()):
                raise BridgeError(key + " must be 1–64 printable characters without / or surrounding whitespace")
    aliases = entry.get("aliases", [])
    if (not isinstance(aliases, list) or len(aliases) > 8
            or any(not isinstance(a, str) or not ALIAS.fullmatch(a) for a in aliases)
            or len(set(aliases)) != len(aliases)):
        raise BridgeError("Aliases must be up to 8 distinct lowercase short names")
    # A display name must not shadow an immutable ID or the route-handle namespace.
    name = entry.get("display_name", "").casefold()
    if name.startswith("contact:") or (name and name.count(".") == 2):
        raise BridgeError("Display name must not shadow a canonical ID or contact handle")


def describe(policy, pid):
    entry = policy.participants.get(pid, {}) if policy and policy.multi_owner else {}
    return {"id": pid, "display_name": entry.get("display_name", pid),
            "platform": entry.get("platform", entry.get("client")), "client": entry.get("client"),
            "role": entry.get("role"),
            "owner": entry.get("owner"), "name_configured": "display_name" in entry}


def label(contact):
    return " · ".join(str(contact[k]) for k in ("display_name", "platform", "role", "owner") if contact.get(k))


def operator_labels(policy, participants):
    """Compact, distinct labels for the operator's global identity inventory."""
    base = {pid: label(describe(policy, pid)) for pid in participants}
    result = dict(base)
    lengths = {pid: 0 for pid in base}
    while True:
        groups = {}
        for pid, value in result.items():
            groups.setdefault(value.casefold(), []).append(pid)
        collisions = [group for group in groups.values() if len(group) > 1]
        if not collisions:
            return result
        for group in collisions:
            for pid in group:
                lengths[pid] = max(8, lengths[pid] + 4)
                if lengths[pid] > 64:
                    # Even a full digest collision must remain distinguishable.
                    return {p: p for p in base}
                tag = hashlib.sha256(pid.encode()).hexdigest()[:lengths[pid]]
                result[pid] = base[pid] + " [#" + tag + "]"


def handle(source, recipient, conversation):
    binding = json.dumps([source, recipient, conversation], separators=(",", ":"))
    return "contact:" + hashlib.sha256(binding.encode()).hexdigest()[:20]


def contacts(policy, source, routes):
    result = []
    for conversation, sender, recipient in routes:
        if sender != source:
            continue
        info = describe(policy, recipient)
        entry = policy.participants[recipient] if policy and policy.multi_owner else {}
        result.append({"recipient": recipient, "conversation_id": conversation,
                       "send_to": handle(source, recipient, conversation),
                       **{k: v for k, v in info.items() if k != "id"},
                       "aliases": list(entry.get("aliases", []))})
    return result


def annotate(policy, row):
    """Fresh annotations, never persisted or included in message fingerprints."""
    source = describe(policy, row["source"])
    recipient = describe(policy, row["recipient"])
    return {**row, "source_contact": source, "recipient_contact": recipient,
            "header": label(source) + " → " + label(recipient)}


def resolve(policy, source, selector, conversation, choices, parent=None):
    if not isinstance(selector, str) or not selector or len(selector) > 128:
        raise BridgeError("Recipient must be a canonical ID, send_to handle, or exact directory name")
    if conversation is not None and not isinstance(conversation, str):
        raise BridgeError("Invalid conversation route", 403)
    # Canonical IDs always retain their original meaning, even when unavailable.
    canonical = ((selector in AGENTS and (not policy or not policy.multi_owner))
                 or (policy and selector in policy.agents))
    if canonical:
        return selector, conversation if conversation is not None else (parent["conversation_id"] if parent else None)
    candidates = []
    for contact in choices:
        if conversation is not None and contact["conversation_id"] != conversation:
            continue
        if selector.startswith("contact:"):
            matches = selector == contact["send_to"]
        else:
            owner, separator, name = selector.partition("/")
            if not separator:
                name, owner = owner, None
            # Friendly names are scoped to the sender's owner. Cross-owner
            # contacts require an explicit owner/name or the listed route handle.
            namespace = owner if separator else describe(policy, source)["owner"]
            matches = (namespace == contact["owner"] and name.casefold() in
                       [contact["display_name"].casefold(), *contact["aliases"]])
        if matches:
            candidates.append(contact)
    if parent:
        # Never resolve a renamed/reused alias into a different reply route.
        candidates = [c for c in candidates if c["recipient"] == parent["source"]
                      and c["conversation_id"] == parent["conversation_id"]]
    if not candidates:
        raise BridgeError("Recipient is unavailable in this scope; refresh list_contacts and use its send_to handle", 403)
    if len(candidates) != 1:
        options = [{"name": label(c), "send_to": c["send_to"], "conversation_id": c["conversation_id"]}
                   for c in candidates]
        raise BridgeError("Ambiguous recipient; choose a send_to handle: " + json.dumps(options, ensure_ascii=False), 409)
    return candidates[0]["recipient"], candidates[0]["conversation_id"]
