# Candidate persistence and signed map layout

This source is NOT installed, signed, approved or activated. Do not copy a test
fixture or synthetic approval registry into production.

## Avatar backend copies

Run prepare_avatar_backend.py with an exact reviewed backend source and a fresh
external output. It checks the two original SHA-256 values before copying and
changes only safe_avatar/profile handling in the existing Admin.php and Actions.php.
The API and tunnel-admin variants keep their different HTTP security preambles.
It does not create accounts/directories, change permissions, write a database or
install configuration. The fixture Protocol.php is a local test dependency, not
an instruction to replace production Protocol.php.

Provisioning later must create /var/lib/guyi-access/avatars outside release trees.
For the observed host, a reviewed root-controlled preparation can give directory
ownership guyi-access:www-data and mode2750; new files use0640. This needs native
Linux identity/ACL verification before approval. Never make PHP code writable.
GUYI_AVATAR_DIR is a trusted process setting, never a request parameter.

Embed rendered gamesense-avatar-locations.conf ONLY in the loopback-admin server,
before its generic assets regex. Keep packaged assets unchanged. The legacy
random-avatar compatibility alias is narrow; migrate only validated existing
avatar files when a separate preparation operation is approved.

Uploads are validated before profile updates. SQL changes are transactional and
an observed rollback removes only the new, unchanged owned PNG. When commit
outcome is unknown, the PNG is retained for reconciliation; deleting a possibly
referenced image would be unsafe. No old avatar is deleted by this change.

## Signed map release

deploy/build_release.py assembles a fresh UNSIGNED candidate from the supplied
binary, two authority PHP files and the exact37 existing dist/maps assets.
The new closed policy requires40 signed leaves, rejects missing/tampered/extra
files and symlinked parents. It intentionally rejects the former three-file
manifest. The old3fe1 release and970a maintenance plan must remain immutable;
new staging needs a NEW manifest, signature, backend-tree hashes and plan.

The rendered data unit explicitly uses -mapimg /opt/gamesense-radar/current/maps.
Assets stay immutable/read-only and map HTTP routes remain device-authorized.
Missing assets still produce map_required, never world coordinates or local
parsing fallback. Raster dimensions do not replace the1024 calibration frame.
The local tests are not real gameplay/map calibration acceptance.

## Verification limits

The Windows fixture uses real PHP8.5/GD and sodium Ed25519 with disposable test
keys, synthetic database state, and actual filesystem operations. It is not
Linux PHP8.2-FPM, root ownership/mode, Nginx alias parsing or systemd acceptance.
Those native checks, full valid-card/Windows-client/game flow, production fault
recovery, signing and maintenance activation remain separate scoped operations.
