// Shared in-memory REGF hive builder, sourced from the winreg-testutil crate so
// every consumer shares one definition (no copy-drift).
pub use winreg_testutil as hive_builder;
