# QuarkShield central-plane DB backup

`pg-backup.sh` dumps the `pqc-scanner-db` container's Postgres database to
`/opt/backups/quarkshield/quarkshield_<timestamp>.sql.gz`, keeps 14 days, and
refuses to keep an empty/truncated dump.

## Install on the VPS (2 AM daily)
```
chmod +x /opt/desktop-pqc-scanner/scripts/pg-backup.sh
# add the cron (idempotent — removes any prior copy of this line first)
( crontab -l 2>/dev/null | grep -v 'pg-backup.sh' ; \
  echo '0 2 * * * /opt/desktop-pqc-scanner/scripts/pg-backup.sh >> /var/log/quarkshield-backup.log 2>&1' ) | crontab -
# run once now to verify
/opt/desktop-pqc-scanner/scripts/pg-backup.sh
```

## Restore
```
gunzip -c /opt/backups/quarkshield/quarkshield_<ts>.sql.gz \
  | docker exec -i pqc-scanner-db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
```

## Notes
- Env overrides: `QS_BACKUP_DIR`, `QS_BACKUP_RETAIN_DAYS`, `QS_DB_CONTAINER`.
- This is a host-local backup; for off-site safety also enable a provider VPS
  snapshot, or copy `/opt/backups/quarkshield` to object storage.
- Tenant pods (e.g. spinovation :5434) have their own DBs — back them up the
  same way against their own containers.
