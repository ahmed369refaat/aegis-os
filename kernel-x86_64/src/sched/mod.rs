//! Scheduling context (PR-1.4): today the single-run ring-3 launch
//! pair; Stage 4 grows this into real per-CPU runqueues around the same
//! `UserContext`/`UserRun` types.
pub mod context;
