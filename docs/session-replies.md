# Replies to trusted automatic sessions

When a private trusted-session backend is already enabled, an authenticated,
approved incoming message makes its active same-owner automatic sender visible
in Ember's `list_contacts`. The return contact uses the original conversation.
`stage_message` requires the original message ID as `reply_to` and a stable new
`message_id`. Acknowledged questions remain replyable.

Return access requires the backend's current dynamic-role inventory, the
`ember_outbound` profile, an active lease and generation, explicit forward route,
matching owner bindings, and MCP provenance. It never derives permission from a
sender's name alone. Static one-way grants and cross-owner recipients gain no
implicit return access. Replies retain normal approval, provenance, deduplication,
hop and rate limits; reads and incoming replies do not renew recipient lifetimes.

This module does not install or enable the private account/session backend.
Canonical installations without that backend retain their existing directed
grants. The reply resolver reads the backend's existing policy snapshot and
message store; it does not change credentials, enrollment or wake configuration.
The backend must refresh the policy for normal scopes and recheck active leases
for message delivery, as before. Expired or revoked contacts remain unavailable;
a genuine same-context resume uses the existing lifecycle process.

The installed backend source is newer than canonical `main`. The return-route
calculation therefore lives in `babel/session_replies.py`, shared by policy
discovery and send authorization, rather than importing the unpublished account,
native hook, enrollment and wake implementations into this repository. Deployment
of any running backend is a separate operator action.
