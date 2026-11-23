# Local datasets

Keep downloaded archives and extracted logs in this folder. Dataset files are ignored by Git; this repository intentionally contains no third-party raw records.

- OpenSSH: `openssh/OpenSSH_2k.log` for the Loghub sample or a full OpenSSH text log at that path.
- NASA: `nasa/NASA_access_log_Jul95` and `nasa/NASA_access_log_Aug95` (plain text, extracted from the official archives).

See the root README for source links, download steps, and use conditions. Override paths with `OPENSSH_LOG_PATH`, `NASA_JULY_LOG_PATH`, and `NASA_AUGUST_LOG_PATH`.
