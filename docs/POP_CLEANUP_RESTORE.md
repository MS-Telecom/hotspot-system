# POP Cleanup Restore

## Adjustments made
- Restored authorization flow to keep `authorizeAccess()` and `radius_replies` in the approval path for paid plans, test access, and active session revalidation.
- Added a safe POP cleanup queue for deletions instead of deleting the POP row immediately.
- Added `cleanup_hotspot_pop` support in the POP commands pipeline.
- Added final cleanup execution after the MikroTik confirms the cleanup command.
- Added a POP-missing guard so deleted POPs do not keep reauthorizing access.

## Cleanup behavior
- The generated cleanup script removes only POP-tagged hotspot resources.
- It targets tagged scheduler, hotspot, hotspot profile, hotspot user profile, walled-garden, radius, DHCP, pools, bridge ports, bridges, VLANs, NAT, files, and POP API user entries when the comment/tag matches the POP.
- It does not remove generic PPPoE, WAN, or unrelated bridge/VLAN/firewall settings.

## Safety model
- The POP stays in `pending_cleanup` until the MikroTik sends command completion.
- After confirmation, the backend archives/removes the POP and revokes related sessions/payments/free trials.
- Repeated cleanup commands are idempotent because removals are wrapped in safe MikroTik `:do { } on-error={}` blocks.