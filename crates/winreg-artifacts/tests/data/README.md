# Test Data — winreg-artifacts

Most tests build synthetic REGF hives in memory via `tests/common/hive_builder.rs`
(no committed fixtures). One integration test validates against a **real** SYSTEM
hive that is consumed via an environment variable, not committed to git.

For the fleet-wide corpus inventory (every repo, real vs synthetic, provenance +
licenses) see [`issen/docs/corpus-catalog.md`](https://github.com/SecurityRonin/issen/blob/main/docs/corpus-catalog.md).

## Real, env-path artifacts (not committed)

### DC01 SYSTEM hive — DFIR Madness "Stolen Szechuan Sauce" (Case 001)

Consumed by `tests/svc_diff_tests.rs::dc01_real_hive_resolves_svchost_servicedlls`,
which validates `svc_diff` ServiceDll / FailureCommand resolution through the
offline `Select\Current → ControlSet00N` indirection on real svchost-hosted
services. The test is **env-gated**: it skips loudly when the env var is unset.

- **Env var:** `WINREG_DC01_SYSTEM` → absolute path to the extracted DC01 SYSTEM hive.
- **Source:** DFIR Madness — "The Case of the Stolen Szechuan Sauce" (Case 001), by James Smith.
- **Site:** <https://dfirmadness.com/the-stolen-szechuan-sauce/> (may be down) ·
  **Mirror:** <https://mimircyber.com/the-case-of-the-stolen-szechuan-sauce/>
- **Host:** CitadelDC01 (Windows Server 2012 R2 / build 9600).
- **Extracted hive MD5:** `05cd86230d5bdbcade8fd6da1d5313a4` (the `SYSTEM` registry hive).
- **In the issen corpus at:** `issen/tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives/SYSTEM`
  (gitignored there; downloaded manually — see the issen tests/data README).
- **Ground truth used by the test** (captured 2026-06-22 from the hash above):
  - 453 services total; **117** carry a `Parameters\ServiceDll`; **3** carry a `FailureCommand`.
  - `Dnscache → %SystemRoot%\System32\dnsrslvr.dll`
  - `Schedule → %systemroot%\system32\schedsvc.dll`
  - `BITS → %SystemRoot%\System32\qmgr.dll`
  - `MSiSCSI` FailureCommand `customScript.cmd` (the other two are `not used`).
- **License / redistribution:** challenge image is **not** redistributed by this repo;
  it is downloaded by the analyst and referenced via `WINREG_DC01_SYSTEM`.

Run the real-data validation with:

```bash
WINREG_DC01_SYSTEM="$HOME/src/issen/tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives/SYSTEM" \
  cargo test -p winreg-artifacts --test svc_diff_tests dc01_real_hive_resolves_svchost_servicedlls
```
