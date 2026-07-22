# Real validation captures

Raw PCAP files in this directory are deliberately ignored by Git. The tracked `manifest.json` records the authoritative source page, archive URL, extracted size, and SHA-256 checksum for each validation sample.

Verify files already present locally:

```powershell
python tools\fetch_real_pcaps.py --verify-only
```

Download and extract missing captures only in an isolated analysis environment. Read the source site's handling warning and current archive-password instructions first:

```powershell
$env:NETTRACE_PCAP_PASSWORD = "<password from source site>"
python tools\fetch_real_pcaps.py --accept-risk
```

The fetcher refuses network downloads unless `--accept-risk` is supplied and verifies every extracted PCAP before reporting success.
