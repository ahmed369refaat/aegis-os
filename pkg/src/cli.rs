//! The command line: parsing, dispatch, and human output for the
//! eleven commands.
//!
//! Output goes through `core::fmt::Write` (a line buffer on the
//! target, stdout on the host) — no allocator anywhere. Every
//! mutating command starts with journal recovery, so an interrupted
//! transaction is rolled back before anything new is considered.
//!
//! Commands:
//! `install <name>[@<ver>] [--force-downgrade]`, `remove <name>`,
//! `update [<name>]`, `upgrade`, `list`, `info <name>`,
//! `verify [<name>]`, `search <query>`, `repo add <url> <pubkey>`,
//! `repo list`, `audit`.
//!
//! ## Privilege
//!
//! Mutating commands are root-only *in effect*: the `/pkg` tree's
//! Unix permissions are the enforcement (the PM domain holds the
//! write capability; the PM has no uid syscall by design — see
//! BUILD.md).

use crate::crypto::ed25519;
use crate::database::{self, DbState, InstalledPkg, PkgPaths, RepoEpochs};
use crate::error::{Error, ErrorKind, Result};
use crate::limits;
use crate::manifest::{SemVer, VersionReq};
use crate::repository::{
    parse_index, read_small_file, BrokerRepository as BrokerRepoWrap, LocalRepository,
    NetTransport, RepoConfig, RepoIndex,
};
use crate::solver::{Candidate, Installed as InstalledLite, PlanOp, Solver};
use crate::transaction::Transaction;
use crate::{FileKind, OpenFlags, Path};

/// Run one command. `args` excludes the program name. Returns the
/// exit code (0 success, 1 handled failure, 2 usage).
pub fn run_cli(
    args: &[&[u8]],
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    net: Option<&mut dyn NetTransport>,
    out: &mut dyn core::fmt::Write,
) -> i32 {
    if args.is_empty() {
        let _ = usage(out);
        return 2;
    }
    let r: Result<i32> = match args[0] {
        b"install" => cmd_install(&args[1..], fs, paths, net, out),
        b"remove" => cmd_remove(&args[1..], fs, paths, out),
        b"update" => cmd_update(&args[1..], fs, paths, net, out),
        b"upgrade" => cmd_upgrade(fs, paths, net, out),
        b"list" => cmd_list(fs, paths, out),
        b"info" => cmd_info(&args[1..], fs, paths, out),
        b"verify" => cmd_verify(&args[1..], fs, paths, out),
        b"search" => cmd_search(&args[1..], fs, paths, out),
        b"repo" => cmd_repo(&args[1..], fs, paths, out),
        b"audit" => cmd_audit(fs, paths, out),
        _ => Err(Error::new(ErrorKind::CliUsage, "unknown command")),
    };
    match r {
        Ok(code) => code,
        Err(e) => {
            let _ = writeln!(out, "{e}");
            1
        }
    }
}

fn usage(out: &mut dyn core::fmt::Write) -> core::fmt::Result {
    writeln!(
        out,
        "pkg — the AegisOS package manager\n\
         commands:\n\
         \x20 pkg install <name>[@<version>] [--force-downgrade]\n\
         \x20 pkg remove <name>\n\
         \x20 pkg update [<name>]\n\
         \x20 pkg upgrade\n\
         \x20 pkg list\n\
         \x20 pkg info <name>\n\
         \x20 pkg verify [<name>]\n\
         \x20 pkg search <query>\n\
         \x20 pkg repo add <url> <pubkey-hex>\n\
         \x20 pkg repo list\n\
         \x20 pkg audit"
    )
}

// ── tiny no-alloc helpers ──

/// Print a byte slice as text (lossy, one byte = one char; all
/// manager-visible text is validated ASCII by the parsers).
struct Sv<'x>(&'x [u8]);

impl core::fmt::Display for Sv<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for &b in self.0 {
            if b.is_ascii_graphic() || b == b' ' {
                write!(f, "{}", b as char)?;
            } else {
                write!(f, "\\x{:02x}", b)?;
            }
        }
        Ok(())
    }
}

/// A namespaced install target.
#[derive(Clone, Copy)]
struct Target {
    name: [u8; limits::MAX_NAME],
    name_len: u8,
    req: VersionReq,
}

impl Target {
    fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

fn make_target(name: &[u8], req: VersionReq) -> Result<Target> {
    if name.len() > limits::MAX_NAME || name.is_empty() {
        return Err(Error::new(ErrorKind::TooLarge, "target name above cap"));
    }
    let mut t = Target {
        name: [0; limits::MAX_NAME],
        name_len: name.len() as u8,
        req,
    };
    t.name[..name.len()].copy_from_slice(name);
    Ok(t)
}

/// Fixed-capacity target list.
struct Targets {
    items: [Target; 32],
    len: usize,
}

impl Targets {
    fn new() -> Self {
        Targets {
            items: [Target {
                name: [0; limits::MAX_NAME],
                name_len: 0,
                req: VersionReq::any(),
            }; 32],
            len: 0,
        }
    }

    fn push(&mut self, t: Target) -> Result<()> {
        if self.len >= 32 {
            return Err(Error::new(ErrorKind::TooLarge, "too many targets"));
        }
        self.items[self.len] = t;
        self.len += 1;
        Ok(())
    }
}

/// Parse `name[@version]`.
fn parse_target(spec: &[u8]) -> Result<(&[u8], VersionReq)> {
    if let Some(at) = spec.iter().position(|&c| c == b'@') {
        let (name, ver) = (&spec[..at], &spec[at + 1..]);
        let v = SemVer::parse(ver)?;
        Ok((name, VersionReq::exact(v)))
    } else {
        Ok((spec, VersionReq::any()))
    }
}

fn namespace_of(name: &[u8]) -> Result<&[u8]> {
    let cut = name
        .iter()
        .position(|&c| c == b'/')
        .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "name must be repo/pkg"))?;
    Ok(&name[..cut])
}

// ── repository loading ──

/// One repository loaded end-to-end (config + verified index).
struct LoadedRepo {
    cfg: RepoConfig,
    index: RepoIndex,
}

const MAX_REPOS: usize = 16;

/// Fixed-capacity repo list.
struct RepoList {
    items: [Option<LoadedRepo>; MAX_REPOS],
    len: usize,
}

impl RepoList {
    fn new() -> Self {
        RepoList {
            items: [const { None }; MAX_REPOS],
            len: 0,
        }
    }

    fn push(&mut self, lr: LoadedRepo) -> Result<()> {
        if self.len >= MAX_REPOS {
            return Err(Error::new(ErrorKind::TooLarge, "repo cap"));
        }
        self.items[self.len] = Some(lr);
        self.len += 1;
        Ok(())
    }

    fn iter(&self) -> impl Iterator<Item = &LoadedRepo> {
        self.items.iter().filter_map(Option::as_ref)
    }
}

/// Load every configured repository's index, verifying signatures
/// and the anti-replay epochs; updates `epochs` (observed pairs are
/// persisted by the caller after success).
fn load_repos(
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    net: &mut Option<&mut dyn NetTransport>,
    epochs: &mut RepoEpochs,
) -> Result<RepoList> {
    let configs = list_repo_configs(fs, paths)?;
    let anchors = crate::repository::TrustAnchors::load(fs, &paths.trust_path())?;
    let mut out = RepoList::new();
    for cfg in configs.items[..configs.len].iter() {
        let cfg = cfg.clone().unwrap_or_else(dump_config);
        // fetch/verify the index bytes once, then try the
        // chain-anchored interpretation against each anchor, then
        // the pinned (root-less) one
        // the raw index bytes in a fixed buffer (no allocator);
        // `idx_len` carries the real length
        let mut ibytes = [0u8; limits::MAX_INDEX];
        let idx_len: usize = if cfg.local {
            let repo = LocalRepository::new(cfg.url(), cfg.slug())?;
            read_small_file(fs, &repo.index_path(), &mut ibytes)?
        } else {
            match net.as_deref_mut() {
                Some(t) => {
                    let mut br = BrokerRepoWrap::new(t, &paths.cache_dir(), cfg.slug(), cfg.url())?;
                    br.fetch_index(&mut ibytes)?
                }
                None => {
                    return Err(Error::new(
                        ErrorKind::CliUsage,
                        "network repository configured but no transport in this build",
                    ));
                }
            }
        };
        let bytes = &ibytes[..idx_len];
        let mut idx: Option<RepoIndex> = None;
        let mut first_err: Option<Error> = None;
        for anchor in anchors.keys[..anchors.count as usize].iter() {
            match parse_index(bytes, cfg.slug(), &cfg.key, Some(anchor), false) {
                Ok(parsed) => {
                    idx = Some(parsed);
                    break;
                }
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        if idx.is_none() {
            match parse_index(bytes, cfg.slug(), &cfg.key, None, cfg.pinned) {
                Ok(parsed) => idx = Some(parsed),
                Err(e) => {
                    return Err(first_err.unwrap_or(e));
                }
            }
        }
        let Some(idx) = idx else {
            return Err(Error::new(ErrorKind::Corruption, "index parse exhausted"));
        };
        // anti-replay: refuse epoch regressions / same-epoch mutation
        epochs.check(cfg.slug(), idx.epoch, &idx.digest)?;
        epochs.observe(cfg.slug(), idx.epoch, idx.digest)?;
        out.push(LoadedRepo { cfg, index: idx })?;
    }
    Ok(out)
}

fn dump_config() -> RepoConfig {
    RepoConfig {
        slug: [0; limits::MAX_NAME],
        slug_len: 0,
        url: [0; 128],
        url_len: 0,
        key: [0; 32],
        pinned: false,
        local: true,
    }
}

const MAX_CONFIGS: usize = 16;

/// Fixed-capacity config list.
struct ConfigList {
    items: [Option<RepoConfig>; MAX_CONFIGS],
    len: usize,
}

impl ConfigList {
    fn empty() -> Self {
        ConfigList {
            items: [const { None }; MAX_CONFIGS],
            len: 0,
        }
    }
}

fn list_repo_configs(fs: &mut dyn crate::Fs, paths: &PkgPaths) -> Result<ConfigList> {
    let mut out = ConfigList::empty();
    let dir = paths.repos_dir();
    match fs.stat(&dir) {
        Ok(st) if st.kind == FileKind::Dir => {}
        _ => return Ok(out),
    }
    let fd = fs.open(&dir, OpenFlags::RDONLY | OpenFlags::DIRECTORY)?;
    let mut names_buf = [0u8; 2048];
    loop {
        let n = fs.getdents(fd, &mut names_buf)?;
        if n == 0 {
            break;
        }
        let mut pos = 0usize;
        while pos < n {
            let rel = &names_buf[pos..n];
            let name_len = rel.iter().position(|&b| b == 0).unwrap_or(rel.len());
            let name = &rel[..name_len];
            pos += name_len + 1;
            if name.ends_with(b".repo") {
                let mut p = dir;
                if p.push(name).is_ok() {
                    let mut buf = [0u8; 300];
                    if let Ok(n) = read_small_file(fs, &p, &mut buf) {
                        if let Ok(cfg) = RepoConfig::parse(&buf[..n]) {
                            if out.len < MAX_CONFIGS {
                                out.items[out.len] = Some(cfg);
                                out.len += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = fs.close(fd);
    Ok(out)
}

const MAX_CANDIDATES: usize = limits::MAX_REPO_PACKAGES;

/// The shared candidate-universe buffer (the caller owns it so the
/// solver borrows the same memory — one big stack array, not two).
const ZERO_DEP: crate::solver::DepClause = crate::solver::DepClause {
    name: [0; limits::MAX_NAME],
    name_len: 0,
    req: VersionReq::any(),
};

const ZERO_CANDIDATE: Candidate = Candidate {
    name: [0; limits::MAX_NAME],
    name_len: 0,
    version: SemVer::zero(),
    deps: [ZERO_DEP; limits::MAX_DEPS],
    deps_len: 0,
    conflicts: [[0; limits::MAX_NAME]; limits::MAX_RELATIONS],
    conflicts_len: [0; limits::MAX_RELATIONS],
    conflicts_len_total: 0,
    provides: [[0; limits::MAX_NAME]; limits::MAX_RELATIONS],
    provides_len: [0; limits::MAX_RELATIONS],
    provides_len_total: 0,
};

/// Fill `universe` (a fixed caller-owned array) with every repo's
/// packages, each header signature-verified before it can
/// participate in resolution (supply chain: an unsigned or
/// mis-signed package is simply not solvable). Returns the count.
fn fill_universe(
    fs: &mut dyn crate::Fs,
    repos: &RepoList,
    universe: &mut [Candidate],
) -> Result<usize> {
    let mut len = 0usize;
    for lr in repos.iter() {
        let repo = LocalRepository::new(lr.cfg.url(), lr.cfg.slug())?;
        for i in 0..lr.index.count as usize {
            if len == universe.len() {
                return Err(Error::new(ErrorKind::TooLarge, "universe cap"));
            }
            let entry = &lr.index.entries[i];
            let path = repo.package_path(entry.name(), &entry.version)?;
            let fd = match fs.open(&path, OpenFlags::RDONLY) {
                Ok(fd) => fd,
                Err(_) => continue, // index lists a file the repo lacks
            };
            let mut src = crate::package::FsSource::new(fs, fd);
            let hdr = crate::package::read_header(&mut src);
            let _ = fs.close(fd);
            if let Ok(h) = hdr {
                if h.verify_signature(&lr.cfg.key).is_ok() {
                    universe[len] = Candidate::from_manifest(&h.manifest)?;
                    len += 1;
                }
            }
        }
    }
    Ok(len)
}

const MAX_INSTALLED_LITE: usize = limits::MAX_INSTALLED;

/// Fixed installed list.
struct InstalledList {
    items: [InstalledLite; MAX_INSTALLED_LITE],
    len: usize,
}

fn installed_lite(fs: &mut dyn crate::Fs, paths: &PkgPaths) -> Result<InstalledList> {
    let state = DbState::load(fs, &paths.state_path())?;
    let mut out = InstalledList {
        items: [InstalledLite {
            name: [0; limits::MAX_NAME],
            name_len: 0,
            version: SemVer::zero(),
        }; MAX_INSTALLED_LITE],
        len: 0,
    };
    for name_buf in state.names[..state.count as usize].iter() {
        let end = name_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(limits::MAX_NAME);
        let name = &name_buf[..end];
        if let Ok(rec) = database::load_record(fs, paths, name) {
            if out.len < MAX_INSTALLED_LITE {
                let mut il = InstalledLite {
                    name: [0; limits::MAX_NAME],
                    name_len: name.len() as u8,
                    version: rec.manifest.version,
                };
                il.name[..name.len()].copy_from_slice(name);
                out.items[out.len] = il;
                out.len += 1;
            }
        }
    }
    Ok(out)
}

fn package_path_for(repos: &RepoList, cand: &Candidate) -> Result<Path> {
    let slug = namespace_of(cand.name())?;
    for lr in repos.iter() {
        if lr.cfg.slug() == slug {
            let repo = LocalRepository::new(lr.cfg.url(), lr.cfg.slug())?;
            // K23: the candidate's OWN version — the repo file is
            // version-qualified, so the plan's chosen version is the
            // file the transaction must read.
            return repo.package_path(cand.name(), &cand.version);
        }
    }
    Err(Error::new(
        ErrorKind::UnknownRepo,
        "package's repo not configured",
    ))
}

fn repo_slug_for(repos: &RepoList, name: &[u8]) -> Result<VecSlug> {
    let slug = namespace_of(name)?;
    for lr in repos.iter() {
        if lr.cfg.slug() == slug {
            let mut b = [0u8; limits::MAX_NAME];
            b[..slug.len()].copy_from_slice(slug);
            return Ok(VecSlug {
                bytes: b,
                len: slug.len() as u8,
            });
        }
    }
    Err(Error::new(
        ErrorKind::UnknownRepo,
        "package's repo not configured",
    ))
}

/// Owned slug.
struct VecSlug {
    bytes: [u8; limits::MAX_NAME],
    len: u8,
}

fn repo_key_for(repos: &RepoList, name: &[u8]) -> Result<ed25519::PublicKey> {
    let slug = namespace_of(name)?;
    for lr in repos.iter() {
        if lr.cfg.slug() == slug {
            return Ok(lr.cfg.key);
        }
    }
    Err(Error::new(
        ErrorKind::UnknownRepo,
        "package's repo not configured",
    ))
}

fn print_plan_op(out: &mut dyn core::fmt::Write, op: &PlanOp) -> core::fmt::Result {
    match op {
        PlanOp::Install(c) => {
            let mut vb = [0u8; 40];
            let n = c.version.write_bytes(&mut vb);
            writeln!(out, "  install {} {}", Sv(c.name()), Sv(&vb[..n]))
        }
        PlanOp::Upgrade(c) => {
            let mut vb = [0u8; 40];
            let n = c.version.write_bytes(&mut vb);
            writeln!(out, "  upgrade {} -> {}", Sv(c.name()), Sv(&vb[..n]))
        }
        PlanOp::Remove(name, len) => writeln!(out, "  remove {}", Sv(&name[..*len as usize])),
        PlanOp::Keep(name, len) => writeln!(out, "  keep {}", Sv(&name[..*len as usize])),
    }
}

impl DbState {
    fn upsert_name(&mut self, name: &[u8]) -> Result<()> {
        if name.len() > limits::MAX_NAME {
            return Err(Error::new(ErrorKind::TooLarge, "name above cap"));
        }
        for nb in self.names[..self.count as usize].iter() {
            let end = nb.iter().position(|&b| b == 0).unwrap_or(limits::MAX_NAME);
            if &nb[..end] == name {
                return Ok(());
            }
        }
        if self.count as usize >= limits::MAX_INSTALLED {
            return Err(Error::new(ErrorKind::TooLarge, "installed cap"));
        }
        let i = self.count as usize;
        self.names[i] = [0; limits::MAX_NAME];
        self.names[i][..name.len()].copy_from_slice(name);
        self.count += 1;
        Ok(())
    }

    fn remove_name(&mut self, name: &[u8]) {
        for i in 0..self.count as usize {
            let end = self.names[i]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(limits::MAX_NAME);
            if &self.names[i][..end] == name {
                self.names.copy_within(i + 1..self.count as usize, i);
                self.count -= 1;
                return;
            }
        }
    }
}

fn persist_repo_epochs(
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    epochs: &RepoEpochs,
) -> Result<()> {
    // the db dir may not exist on a fresh system (update runs before
    // any transaction created it)
    let _ = fs.mkdir(paths.root());
    let _ = fs.mkdir(&paths.db_dir());
    let dest = paths.repo_epochs_path();
    let mut tmp = dest;
    tmp.push_last(b".tmp")?;
    let mut buf = [0u8; 4 + 2 + 1 + 16 * (1 + limits::MAX_NAME + 8 + 32)];
    let n = epochs.serialize(&mut buf)?;
    let fd = fs.open(&tmp, OpenFlags::WRONLY | OpenFlags::CREATE)?;
    let mut off = 0usize;
    while off < n {
        let w = fs.write(fd, &buf[off..n])?;
        off += w;
    }
    let _ = fs.sync(fd);
    let _ = fs.close(fd);
    fs.rename(&tmp, &dest)?;
    Ok(())
}

/// The shared solve-and-install path for `install` and `upgrade`.
/// `up_to_date_ok` (upgrade's shape) tolerates a target no repo
/// version beats: an already-latest package resolves to "nothing to
/// do", while `install` keeps the loud `ConstraintUnsat` refusal.
fn do_solve_and_install(
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    net: &mut Option<&mut dyn NetTransport>,
    out: &mut dyn core::fmt::Write,
    targets: &Targets,
    allow_downgrade: bool,
    up_to_date_ok: bool,
) -> Result<i32> {
    // recovery first: an interrupted transaction is rolled back
    crate::transaction::recover(fs, paths)?;
    let mut epochs = RepoEpochs::load(fs, &paths.repo_epochs_path())?;
    let repos = load_repos(fs, paths, net, &mut epochs)?;
    if repos.len == 0 {
        let _ = writeln!(out, "no repositories configured — `pkg repo add` first");
        return Ok(1);
    }
    let mut universe: [Candidate; MAX_CANDIDATES] = [ZERO_CANDIDATE; MAX_CANDIDATES];
    let universe_len = fill_universe(fs, &repos, &mut universe)?;
    let installed = installed_lite(fs, paths)?;
    let mut solver = Solver::new(
        &installed.items[..installed.len],
        &universe[..universe_len],
        allow_downgrade,
    );
    // combined plan across targets
    let mut combined = crate::solver::Plan::empty();
    for target in targets.items[..targets.len].iter() {
        let plan = match solver.resolve_install(target.name(), target.req) {
            Ok(plan) => plan,
            // `pkg upgrade` asking for above(installed): no repo
            // version beats the installed one — that package is
            // simply up to date, not an error.
            Err(e)
                if up_to_date_ok
                    && e.kind() == ErrorKind::ConstraintUnsat
                    && solver.is_up_to_date(target.name(), target.req) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        for op in plan.ops[..plan.count as usize].iter() {
            if combined.count as usize >= limits::MAX_PACKAGES {
                return Err(Error::new(ErrorKind::TooLarge, "combined plan cap"));
            }
            combined.ops[combined.count as usize] = *op;
            combined.count += 1;
        }
    }
    // every target already at its repo's latest: say so and succeed
    // (an empty transaction would still churn the state epoch).
    if combined.count == 0 {
        let _ = writeln!(out, "nothing to do (up to date)");
        persist_repo_epochs(fs, paths, &epochs)?;
        return Ok(0);
    }
    // print the plan BEFORE touching the filesystem
    let _ = writeln!(out, "plan:");
    for op in &combined.ops[..combined.count as usize] {
        let _ = print_plan_op(out, op);
    }
    let _ = writeln!(out, "executing...");
    let mut tx = Transaction::begin(&mut *fs, paths)?;
    let state = DbState::load(tx.fs_mut(), &paths.state_path())?;
    let mut new_state = state.clone();
    new_state.epoch = state.epoch.wrapping_add(1);
    for op in &combined.ops[..combined.count as usize] {
        match op {
            PlanOp::Install(c) | PlanOp::Upgrade(c) => {
                let pkg_path = package_path_for(&repos, c)?;
                let prev = database::load_record(tx.fs_mut(), paths, c.name()).ok();
                let origin = repo_slug_for(&repos, c.name())?;
                let manifest = tx.install_package(
                    &pkg_path,
                    &repo_key_for(&repos, c.name())?,
                    &origin.bytes[..origin.len as usize],
                    new_state.epoch,
                    prev.as_ref(),
                    allow_downgrade,
                )?;
                new_state.upsert_name(manifest.name())?;
            }
            PlanOp::Remove(name, len) => {
                tx.remove_record(&name[..*len as usize])?;
                new_state.remove_name(&name[..*len as usize]);
            }
            PlanOp::Keep(_, _) => {}
        }
    }
    tx.stage_state(&new_state)?;
    tx.commit()?;
    persist_repo_epochs(fs, paths, &epochs)?;
    let _ = writeln!(out, "done");
    Ok(0)
}

// ── commands ──

fn cmd_install(
    args: &[&[u8]],
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    mut net: Option<&mut dyn NetTransport>,
    out: &mut dyn core::fmt::Write,
) -> Result<i32> {
    let mut allow_downgrade = false;
    let mut targets = Targets::new();
    for &a in args {
        if a == b"--force-downgrade" {
            allow_downgrade = true;
        } else {
            let (name, req) = parse_target(a)?;
            targets.push(make_target(name, req)?)?;
        }
    }
    if targets.len == 0 {
        let _ = writeln!(out, "usage: pkg install <name>[@<version>]");
        return Ok(2);
    }
    do_solve_and_install(fs, paths, &mut net, out, &targets, allow_downgrade, false)
}

fn cmd_remove(
    args: &[&[u8]],
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    out: &mut dyn core::fmt::Write,
) -> Result<i32> {
    if args.is_empty() {
        let _ = writeln!(out, "usage: pkg remove <name>");
        return Ok(2);
    }
    let name = args[0];
    crate::transaction::recover(fs, paths)?;
    let installed = installed_lite(fs, paths)?;
    let empty: [Candidate; 0] = [];
    let mut solver = Solver::new(&installed.items[..installed.len], &empty, false);
    let plan = solver.resolve_remove(name)?;
    for op in &plan.ops[..plan.count as usize] {
        let _ = print_plan_op(out, op);
    }
    let state = DbState::load(fs, &paths.state_path())?;
    let mut new_state = state.clone();
    new_state.epoch = state.epoch.wrapping_add(1);
    let mut tx = Transaction::begin(fs, paths)?;
    for op in &plan.ops[..plan.count as usize] {
        if let PlanOp::Remove(nm, len) = op {
            let name = &nm[..*len as usize];
            // remove the files the record owns
            if let Ok(rec) = database::load_record(tx.fs_mut(), paths, name) {
                for entry in &rec.manifest.files[..rec.manifest.files_len as usize] {
                    tx.backup_remove(&entry.path)?;
                }
            }
            tx.remove_record(name)?;
            new_state.remove_name(name);
        }
    }
    tx.stage_state(&new_state)?;
    tx.commit()?;
    let _ = writeln!(out, "done");
    Ok(0)
}

fn cmd_update(
    args: &[&[u8]],
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    mut net: Option<&mut dyn NetTransport>,
    out: &mut dyn core::fmt::Write,
) -> Result<i32> {
    // `update <name>` behaves like `update` here: metadata refresh
    // is repo-wide; per-name refresh is the index the repos share.
    let _ = args;
    crate::transaction::recover(fs, paths)?;
    let mut epochs = RepoEpochs::load(fs, &paths.repo_epochs_path())?;
    let repos = load_repos(fs, paths, &mut net, &mut epochs)?;
    for lr in repos.iter() {
        let _ = writeln!(
            out,
            "{}: epoch {} ({} packages)",
            Sv(lr.cfg.slug()),
            lr.index.epoch,
            lr.index.count
        );
    }
    persist_repo_epochs(fs, paths, &epochs)?;
    Ok(0)
}

fn cmd_upgrade(
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    mut net: Option<&mut dyn NetTransport>,
    out: &mut dyn core::fmt::Write,
) -> Result<i32> {
    crate::transaction::recover(fs, paths)?;
    let installed = installed_lite(fs, paths)?;
    if installed.len == 0 {
        let _ = writeln!(out, "nothing installed");
        return Ok(0);
    }
    // K23: the request per installed package is STRICTLY NEWER, not
    // `any()`. The solver keeps an installed version whenever it
    // satisfies the request, so the old `any()` targets resolved to
    // [keep] forever — `pkg upgrade` was structurally a no-op (found
    // live while building the upgrade lane: the plan printed "keep
    // r1/hello" and the payload never moved). `above(installed)`
    // fails the keep test, walks the candidates newest-first, and
    // the downgrade policy still refuses anything older.
    let mut targets = Targets::new();
    for inst in &installed.items[..installed.len] {
        targets.push(make_target(inst.name(), VersionReq::above(inst.version))?)?;
    }
    do_solve_and_install(fs, paths, &mut net, out, &targets, false, true)
}

fn cmd_list(
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    out: &mut dyn core::fmt::Write,
) -> Result<i32> {
    let state = DbState::load(fs, &paths.state_path())?;
    for name_buf in state.names[..state.count as usize].iter() {
        let end = name_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(limits::MAX_NAME);
        let name = &name_buf[..end];
        if let Ok(rec) = database::load_record(fs, paths, name) {
            let mut vb = [0u8; 40];
            let n = rec.manifest.version.write_bytes(&mut vb);
            let _ = writeln!(out, "{} {}", Sv(name), Sv(&vb[..n]));
        }
    }
    Ok(0)
}

fn cmd_info(
    args: &[&[u8]],
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    out: &mut dyn core::fmt::Write,
) -> Result<i32> {
    if args.is_empty() {
        let _ = writeln!(out, "usage: pkg info <name>");
        return Ok(2);
    }
    let name = args[0];
    match database::load_record(fs, paths, name) {
        Ok(rec) => {
            let mut vb = [0u8; 40];
            let n = rec.manifest.version.write_bytes(&mut vb);
            let _ = writeln!(
                out,
                "{} {} (installed, epoch {})",
                Sv(name),
                Sv(&vb[..n]),
                rec.epoch
            );
            let _ = writeln!(
                out,
                "  from repo {}, {} files",
                Sv(rec.origin()),
                rec.manifest.files_len
            );
            let _ = writeln!(out, "  {}", Sv(rec.manifest.description()));
            Ok(0)
        }
        Err(e) if e.kind() == ErrorKind::NotInstalled => {
            let _ = writeln!(out, "{} is not installed", Sv(name));
            Ok(1)
        }
        Err(e) => Err(e),
    }
}

fn hash_file(fs: &mut dyn crate::Fs, path: &Path) -> Result<[u8; 32]> {
    use crate::crypto::sha256::Sha256;
    let fd = fs.open(path, OpenFlags::RDONLY)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; limits::IO_CHUNK];
    let res = loop {
        match fs.read(fd, &mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => h.update(&buf[..n]),
            Err(e) => break Err(e),
        }
    };
    let _ = fs.close(fd);
    res?;
    let mut d = [0u8; 32];
    h.finish(&mut d);
    Ok(d)
}

fn verify_package(
    fs: &mut dyn crate::Fs,
    rec: &InstalledPkg,
    out: &mut dyn core::fmt::Write,
) -> Result<usize> {
    let mut bad = 0usize;
    for f in &rec.manifest.files[..rec.manifest.files_len as usize] {
        match fs.stat(&f.path) {
            Ok(st) if st.kind == FileKind::File => {}
            _ => {
                let _ = writeln!(out, "  MISSING {}", Sv(f.path.as_bytes()));
                bad += 1;
                continue;
            }
        }
        let d = hash_file(fs, &f.path)?;
        if !crate::crypto::ct_eq(&d, &f.sha256) {
            let _ = writeln!(out, "  CHANGED {}", Sv(f.path.as_bytes()));
            bad += 1;
        }
    }
    Ok(bad)
}

fn cmd_verify(
    args: &[&[u8]],
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    out: &mut dyn core::fmt::Write,
) -> Result<i32> {
    crate::transaction::recover(fs, paths)?;
    if !args.is_empty() {
        let rec = database::load_record(fs, paths, args[0])?;
        let bad = verify_package(fs, &rec, out)?;
        let _ = if bad == 0 {
            writeln!(
                out,
                "{}: OK ({} files)",
                Sv(args[0]),
                rec.manifest.files_len
            )
        } else {
            writeln!(out, "{}: {} problems", Sv(args[0]), bad)
        };
        return Ok(if bad == 0 { 0 } else { 1 });
    }
    let state = DbState::load(fs, &paths.state_path())?;
    let mut total_bad = 0usize;
    for name_buf in state.names[..state.count as usize].iter() {
        let end = name_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(limits::MAX_NAME);
        let name = &name_buf[..end];
        if let Ok(rec) = database::load_record(fs, paths, name) {
            let _ = writeln!(out, "{}:", Sv(name));
            total_bad += verify_package(fs, &rec, out)?;
        }
    }
    Ok(if total_bad == 0 { 0 } else { 1 })
}

fn cmd_search(
    args: &[&[u8]],
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    out: &mut dyn core::fmt::Write,
) -> Result<i32> {
    if args.is_empty() {
        let _ = writeln!(out, "usage: pkg search <query>");
        return Ok(2);
    }
    let query = args[0];
    let mut epochs = RepoEpochs::empty();
    let mut none = None;
    let repos = load_repos(fs, paths, &mut none, &mut epochs)?;
    let mut hits = 0usize;
    for lr in repos.iter() {
        for e in lr.index.entries[..lr.index.count as usize].iter() {
            if substring(e.name(), query) {
                let mut vb = [0u8; 40];
                let n = e.version.write_bytes(&mut vb);
                let _ = writeln!(out, "{} {} ({} bytes)", Sv(e.name()), Sv(&vb[..n]), e.size);
                hits += 1;
            }
        }
    }
    if hits == 0 {
        let _ = writeln!(out, "no matches");
    }
    Ok(0)
}

fn substring(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

fn cmd_repo(
    args: &[&[u8]],
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    out: &mut dyn core::fmt::Write,
) -> Result<i32> {
    if args.is_empty() {
        let _ = writeln!(
            out,
            "usage: pkg repo add <url> <pubkey-hex> | pkg repo list"
        );
        return Ok(2);
    }
    match args[0] {
        b"add" => {
            if args.len() < 3 {
                let _ = writeln!(out, "usage: pkg repo add <url> <pubkey-hex>");
                return Ok(2);
            }
            let url = args[1];
            let keyhex = args[2];
            let mut key = [0u8; 32];
            if !hex32(keyhex, &mut key) {
                return Err(Error::new(
                    ErrorKind::InvalidFormat,
                    "pubkey must be 64 hex chars",
                ));
            }
            let slug = slug_from_url(url)?;
            let local = !url.starts_with(b"net:");
            let cfg = RepoConfig {
                slug: pad_name(slug)?,
                slug_len: slug.len() as u8,
                url: pad_url(url)?,
                url_len: url.len() as u8,
                key,
                pinned: true, // explicit admin trust (TOFU)
                local,
            };
            let mut buf = [0u8; 300];
            let n = cfg.serialize(&mut buf)?;
            ensure_dirs_for(fs, paths)?;
            let mut rp = paths.repos_dir();
            rp.push(slug)?;
            rp.push_last(b".repo")?;
            let fd = fs.open(&rp, OpenFlags::WRONLY | OpenFlags::CREATE | OpenFlags::EXCL)?;
            let mut off = 0usize;
            while off < n {
                let w = fs.write(fd, &buf[off..n])?;
                off += w;
            }
            let _ = fs.sync(fd);
            let _ = fs.close(fd);
            let _ = writeln!(
                out,
                "repository {} pinned (TOFU — verify this key out-of-band!)",
                Sv(slug)
            );
            Ok(0)
        }
        b"list" => {
            let repos = list_repo_configs(fs, paths)?;
            for rc in repos.items[..repos.len].iter() {
                if let Some(cfg) = rc.as_ref() {
                    let _ = writeln!(
                        out,
                        "{} {} {}",
                        Sv(cfg.slug()),
                        Sv(cfg.url()),
                        if cfg.local { "local" } else { "broker" }
                    );
                }
            }
            Ok(0)
        }
        _ => {
            let _ = writeln!(out, "unknown repo subcommand");
            Ok(2)
        }
    }
}

fn slug_from_url(url: &[u8]) -> Result<&[u8]> {
    let cut = url
        .iter()
        .rposition(|&c| c == b'/')
        .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "url needs a path"))?;
    let slug = &url[cut + 1..];
    crate::manifest::validate_name_part(slug, "slug")?;
    Ok(slug)
}

fn pad_name(s: &[u8]) -> Result<[u8; limits::MAX_NAME]> {
    if s.len() > limits::MAX_NAME {
        return Err(Error::new(ErrorKind::TooLarge, "name above cap"));
    }
    let mut b = [0u8; limits::MAX_NAME];
    b[..s.len()].copy_from_slice(s);
    Ok(b)
}

fn pad_url(s: &[u8]) -> Result<[u8; 128]> {
    if s.len() > 128 {
        return Err(Error::new(ErrorKind::TooLarge, "url above cap"));
    }
    let mut b = [0u8; 128];
    b[..s.len()].copy_from_slice(s);
    Ok(b)
}

fn ensure_dirs_for(fs: &mut dyn crate::Fs, paths: &PkgPaths) -> Result<()> {
    for d in [paths.root(), &paths.db_dir(), &paths.repos_dir()] {
        match fs.stat(d) {
            Ok(st) if st.kind == FileKind::Dir => {}
            _ => {
                let _ = fs.mkdir(d);
            }
        }
    }
    Ok(())
}

fn hex32(hex: &[u8], out: &mut [u8; 32]) -> bool {
    if hex.len() != 64 {
        return false;
    }
    for i in 0..32 {
        let hi = hex_val(hex[i * 2]);
        let lo = hex_val(hex[i * 2 + 1]);
        match (hi, lo) {
            (Some(a), Some(b)) => out[i] = (a << 4) | b,
            _ => return false,
        }
    }
    true
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn cmd_audit(
    fs: &mut dyn crate::Fs,
    paths: &PkgPaths,
    out: &mut dyn core::fmt::Write,
) -> Result<i32> {
    crate::transaction::recover(fs, paths)?;
    let _ = writeln!(out, "audit:");
    // 1. every installed file matches its record hash, no setuid
    let state = DbState::load(fs, &paths.state_path())?;
    let mut problems = 0usize;
    for name_buf in state.names[..state.count as usize].iter() {
        let end = name_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(limits::MAX_NAME);
        let name = &name_buf[..end];
        match database::load_record(fs, paths, name) {
            Ok(rec) => {
                let _ = writeln!(out, " {}:", Sv(name));
                problems += verify_package(fs, &rec, out)?;
                for entry in &rec.manifest.files[..rec.manifest.files_len as usize] {
                    if let Ok(st) = fs.stat(&entry.path) {
                        if st.perm & !0o777 != 0 {
                            let _ = writeln!(
                                out,
                                "  PERM {} has setuid/sticky bits",
                                Sv(entry.path.as_bytes())
                            );
                            problems += 1;
                        }
                    }
                }
            }
            Err(e) => {
                let _ = writeln!(out, " RECORD {}: {}", Sv(name), e);
                problems += 1;
            }
        }
    }
    // 2. no live lock
    if fs.stat(&paths.lock_path()).is_ok() {
        let _ = writeln!(out, " lock file present (another invocation, or stale)");
        problems += 1;
    }
    let _ = writeln!(out, " {} problems", problems);
    Ok(if problems == 0 { 0 } else { 1 })
}

/// Build a signed index (builder side: tests + repo tooling).
///
/// # Errors
/// [`ErrorKind::TooLarge`] on overflow.
#[cfg(any(test, feature = "signer"))]
#[allow(clippy::type_complexity)]
pub fn build_index_with_hashes(
    slug: &[u8],
    epoch: u64,
    entries: &[(&[u8], crate::manifest::Manifest, [u8; 32], u64)],
    repo_key: &ed25519::SecretKey,
    root_key: Option<&ed25519::SecretKey>,
    out: &mut [u8],
) -> Result<usize> {
    use crate::{wr_bytes, wr_u16, wr_u32, wr_u64};
    let mut pos = 0usize;
    wr_bytes(out, &mut pos, b"AKI1")?;
    wr_u16(out, &mut pos, 1)?;
    wr_bytes(out, &mut pos, &[slug.len() as u8])?;
    wr_bytes(out, &mut pos, slug)?;
    wr_u64(out, &mut pos, epoch)?;
    wr_u32(out, &mut pos, entries.len() as u32)?;
    for (name, m, hash, size) in entries {
        wr_bytes(out, &mut pos, &[name.len() as u8])?;
        wr_bytes(out, &mut pos, name)?;
        wr_u32(out, &mut pos, m.version.major)?;
        wr_u32(out, &mut pos, m.version.minor)?;
        wr_u32(out, &mut pos, m.version.patch)?;
        wr_bytes(out, &mut pos, &[m.version.pre_len])?;
        wr_bytes(out, &mut pos, m.version.pre_bytes())?;
        wr_bytes(out, &mut pos, hash)?;
        wr_u64(out, &mut pos, *size)?;
        let _ = m;
    }
    let repo_sig = ed25519::sign(repo_key, &out[..pos]);
    wr_bytes(out, &mut pos, &repo_sig)?;
    if let Some(rk) = root_key {
        let root_sig = ed25519::sign(rk, &out[..pos]);
        wr_bytes(out, &mut pos, &root_sig)?;
    }
    Ok(pos)
}
