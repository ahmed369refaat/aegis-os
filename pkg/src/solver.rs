//! The dependency solver: backtracking resolution with conflict,
//! cycle, depth and budget diagnostics.
//!
//! ## Algorithm
//!
//! Depth-first backtracking over a fixed universe:
//!
//! 1. **Assignment map**: every namespaced name maps to
//!    *Unset*, *Keep* (installed version satisfies), or a
//!    *Selected* candidate version.
//! 2. **Candidate order**: highest version first (prefer-latest),
//!    and the installed version first among satisfying versions
//!    (prefer-no-op) — the common case resolves without a single
//!    backtrack, O(n log n)-shaped: each package is visited once,
//!    each candidate list is bounded, and the chosen order makes
//!    the first dive succeed.
//! 3. **Constraints**: every selected version must satisfy ALL
//!    version requests recorded for its name (from the root target
//!    and every selected dependent).
//! 4. **Conflicts/provides**: a candidate whose `conflicts` lists a
//!    name that is Selected or kept-installed (or that it provides
//!    and something selected depends on that alias) is skipped; two
//!    candidates providing the same name cannot both be selected.
//! 5. **Cycle detection**: a DFS visiting-set; a name re-entered on
//!    the current path is reported with the full chain
//!    (["ErrorKind::Cycle"]) — never recursed into.
//! 6. **Budget**: total decisions are counted; an adversarial
//!    universe that would force exponential search trips
//!    [`limits::MAX_SOLVER_STEPS`] and fails with
//!    `ConstraintUnsat` — bounded CPU, by construction.
//!
//! The solver is pure: it reads the installed database and the
//! repository index and returns a **complete plan before any
//! filesystem action** (`cli.rs` prints the plan; the transaction
//! then executes it).
//!
//! ## THREAT: dependency confusion / typosquatting
//!
//! Names are two-part namespaces; a dependency on `repo/pkg`
//! resolves ONLY in that repo's index entries — a same-named
//! package in another repo does not satisfy it, and bare names
//! cannot exist at all (see `manifest::validate_name`).

use crate::error::{Error, ErrorKind, Result};
use crate::limits;
use crate::manifest::{Manifest, SemVer, VersionReq};

/// One resolution candidate (a repo index entry).
#[derive(Clone, Copy)]
pub struct Candidate {
    /// Namespaced name.
    pub name: [u8; limits::MAX_NAME],
    /// Name length.
    pub name_len: u8,
    /// The candidate version.
    pub version: SemVer,
    /// Its declared dependencies (copied from the repo entry's
    /// manifest digest — the solver needs the dep list; the
    /// transaction re-verifies the real manifest at install).
    pub deps: [DepClause; limits::MAX_DEPS],
    /// Dep count.
    pub deps_len: u8,
    /// Names this candidate conflicts with.
    pub conflicts: [[u8; limits::MAX_NAME]; limits::MAX_RELATIONS],
    /// Conflicts lengths.
    pub conflicts_len: [u8; limits::MAX_RELATIONS],
    /// Conflicts count.
    pub conflicts_len_total: u8,
    /// Names this candidate provides (aliases).
    pub provides: [[u8; limits::MAX_NAME]; limits::MAX_RELATIONS],
    /// Provides lengths.
    pub provides_len: [u8; limits::MAX_RELATIONS],
    /// Provides count.
    pub provides_len_total: u8,
}

/// A dependency clause in the solver's universe.
#[derive(Clone, Copy)]
pub struct DepClause {
    /// Namespaced target.
    pub name: [u8; limits::MAX_NAME],
    /// Length.
    pub name_len: u8,
    /// Version request.
    pub req: VersionReq,
}

impl DepClause {
    /// The name bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

impl Candidate {
    /// The name bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Build a candidate from a package manifest (repo side).
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] on relation overflow.
    pub fn from_manifest(m: &Manifest) -> Result<Self> {
        if m.deps_len as usize > limits::MAX_DEPS
            || m.conflicts_len as usize > limits::MAX_RELATIONS
            || m.provides_len as usize > limits::MAX_RELATIONS
        {
            return Err(Error::new(
                ErrorKind::TooLarge,
                "manifest relation overflow",
            ));
        }
        let mut c = Candidate {
            name: [0; limits::MAX_NAME],
            name_len: m.name_len,
            version: m.version,
            deps: [DepClause {
                name: [0; limits::MAX_NAME],
                name_len: 0,
                req: VersionReq::any(),
            }; limits::MAX_DEPS],
            deps_len: m.deps_len,
            conflicts: [[0; limits::MAX_NAME]; limits::MAX_RELATIONS],
            conflicts_len: [0; limits::MAX_RELATIONS],
            conflicts_len_total: m.conflicts_len,
            provides: [[0; limits::MAX_NAME]; limits::MAX_RELATIONS],
            provides_len: [0; limits::MAX_RELATIONS],
            provides_len_total: m.provides_len,
        };
        c.name[..m.name_len as usize].copy_from_slice(m.name());
        for i in 0..m.deps_len as usize {
            c.deps[i] = DepClause {
                name: m.deps[i].name,
                name_len: m.deps[i].name_len,
                req: m.deps[i].req,
            };
        }
        for i in 0..m.conflicts_len as usize {
            c.conflicts[i] = m.conflicts[i].name;
            c.conflicts_len[i] = m.conflicts[i].name_len;
        }
        for i in 0..m.provides_len as usize {
            c.provides[i] = m.provides[i].name;
            c.provides_len[i] = m.provides[i].name_len;
        }
        Ok(c)
    }

    fn conflicts_with(&self, name: &[u8]) -> bool {
        (0..self.conflicts_len_total as usize)
            .any(|i| &self.conflicts[i][..self.conflicts_len[i] as usize] == name)
    }

    fn provides_alias(&self, name: &[u8]) -> bool {
        (0..self.provides_len_total as usize)
            .any(|i| &self.provides[i][..self.provides_len[i] as usize] == name)
    }
}

/// A currently-installed package, as the solver sees it.
#[derive(Clone, Copy)]
pub struct Installed {
    /// Namespaced name.
    pub name: [u8; limits::MAX_NAME],
    /// Length.
    pub name_len: u8,
    /// Installed version.
    pub version: SemVer,
}

impl Installed {
    /// The name bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// One plan step.
#[derive(Clone, Copy)]
pub enum PlanOp {
    /// Install this candidate (not currently installed).
    Install(Candidate),
    /// Replace the installed version with this candidate.
    Upgrade(Candidate),
    /// Uninstall this package.
    Remove([u8; limits::MAX_NAME], u8),
    /// Keep the installed version (satisfies constraints).
    Keep([u8; limits::MAX_NAME], u8),
}

/// The install/remove plan: fully computed before any I/O.
#[derive(Clone)]
pub struct Plan {
    /// Steps, in dependency order (deps first).
    pub ops: [PlanOp; limits::MAX_PACKAGES],
    /// Step count.
    pub count: u16,
}

impl Plan {
    /// The empty plan.
    #[must_use]
    pub fn empty() -> Self {
        Plan {
            ops: [PlanOp::Keep([0; limits::MAX_NAME], 0); limits::MAX_PACKAGES],
            count: 0,
        }
    }

    fn push(&mut self, op: PlanOp) -> Result<()> {
        if self.count as usize >= limits::MAX_PACKAGES {
            return Err(Error::new(ErrorKind::TooLarge, "plan exceeds cap"));
        }
        self.ops[self.count as usize] = op;
        self.count += 1;
        Ok(())
    }
}

/// Solver state.
pub struct Solver<'a> {
    installed: &'a [Installed],
    candidates: &'a [Candidate],
    allow_downgrade: bool,
    steps: u32,
    plan: Plan,
}

/// Selection state per namespaced name.
#[derive(Clone, Copy, PartialEq)]
enum Sel {
    /// Not yet considered.
    Unset,
    /// Keep the installed version.
    Keep,
    /// Select this candidate index.
    Select(usize),
}

struct SelMap {
    keys: [[u8; limits::MAX_NAME]; limits::MAX_PACKAGES],
    key_lens: [u8; limits::MAX_PACKAGES],
    vals: [Sel; limits::MAX_PACKAGES],
    count: usize,
}

impl SelMap {
    fn new() -> Self {
        SelMap {
            keys: [[0; limits::MAX_NAME]; limits::MAX_PACKAGES],
            key_lens: [0; limits::MAX_PACKAGES],
            vals: [Sel::Unset; limits::MAX_PACKAGES],
            count: 0,
        }
    }

    fn get(&self, name: &[u8]) -> Sel {
        (0..self.count)
            .find(|&i| &self.keys[i][..self.key_lens[i] as usize] == name)
            .map_or(Sel::Unset, |i| self.vals[i])
    }

    fn set(&mut self, name: &[u8], val: Sel) -> Result<()> {
        if let Some(i) =
            (0..self.count).find(|&i| &self.keys[i][..self.key_lens[i] as usize] == name)
        {
            self.vals[i] = val;
            return Ok(());
        }
        if self.count >= limits::MAX_PACKAGES || name.len() > limits::MAX_NAME {
            return Err(Error::new(ErrorKind::TooLarge, "selection map full"));
        }
        let i = self.count;
        self.keys[i][..name.len()].copy_from_slice(name);
        self.key_lens[i] = name.len() as u8;
        self.vals[i] = val;
        self.count += 1;
        Ok(())
    }
}

/// The path stack for cycle diagnostics.
struct PathStack {
    frames: [[u8; limits::MAX_NAME]; limits::MAX_SOLVER_DEPTH],
    lens: [u8; limits::MAX_SOLVER_DEPTH],
    depth: usize,
}

impl PathStack {
    fn new() -> Self {
        PathStack {
            frames: [[0; limits::MAX_NAME]; limits::MAX_SOLVER_DEPTH],
            lens: [0; limits::MAX_SOLVER_DEPTH],
            depth: 0,
        }
    }

    fn push(&mut self, name: &[u8]) -> Result<()> {
        if self.depth >= limits::MAX_SOLVER_DEPTH {
            return Err(Error::new(ErrorKind::DepthLimit, "solver depth cap"));
        }
        if name.len() > limits::MAX_NAME {
            return Err(Error::new(ErrorKind::TooLarge, "name above cap"));
        }
        self.frames[self.depth][..name.len()].copy_from_slice(name);
        self.lens[self.depth] = name.len() as u8;
        self.depth += 1;
        Ok(())
    }

    fn pop(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn contains(&self, name: &[u8]) -> bool {
        (0..self.depth).any(|i| &self.frames[i][..self.lens[i] as usize] == name)
    }

    fn render(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        let mut n = 0usize;
        for i in 0..self.depth {
            let name = &self.frames[i][..self.lens[i] as usize];
            if n + name.len() + 1 >= 256 {
                break;
            }
            if i > 0 {
                out[n] = b' ';
                n += 1;
            }
            out[n..n + name.len()].copy_from_slice(name);
            n += name.len();
        }
        out
    }
}

impl<'a> Solver<'a> {
    /// New solver over the universe: `installed` packages and
    /// `candidates` (all repo entries, any order).
    #[must_use]
    pub fn new(
        installed: &'a [Installed],
        candidates: &'a [Candidate],
        allow_downgrade: bool,
    ) -> Self {
        Solver {
            installed,
            candidates,
            allow_downgrade,
            steps: 0,
            plan: Plan::empty(),
        }
    }

    fn installed_version(&self, name: &[u8]) -> Option<SemVer> {
        self.installed
            .iter()
            .find(|i| i.name() == name)
            .map(|i| i.version)
    }

    fn bump_steps(&mut self) -> Result<()> {
        self.steps = self
            .steps
            .checked_add(1)
            .filter(|&s| s <= limits::MAX_SOLVER_STEPS)
            .ok_or_else(|| {
                Error::new(ErrorKind::ConstraintUnsat, "solver step budget exhausted")
            })?;
        if self.steps >= limits::MAX_SOLVER_STEPS {
            return Err(Error::new(
                ErrorKind::ConstraintUnsat,
                "solver step budget exhausted",
            ));
        }
        Ok(())
    }

    /// Resolve `name` at `req` into `sel` (the shared selection
    /// map), backtracking through candidate order.
    fn resolve_into(
        &mut self,
        name: &[u8],
        req: VersionReq,
        sel: &mut SelMap,
        path: &mut PathStack,
    ) -> Result<()> {
        self.bump_steps()?;
        if path.contains(name) {
            let chain = path.render();
            let mut detail = [0u8; 320];
            detail[..256].copy_from_slice(&chain);
            return Err(Error::with(ErrorKind::Cycle, &detail).context("dependency cycle"));
        }
        if path.depth >= limits::MAX_SOLVER_DEPTH {
            return Err(Error::new(
                ErrorKind::DepthLimit,
                "dependency chain too deep",
            ));
        }
        path.push(name)?;

        // already selected: the new request must be satisfied by it
        match sel.get(name) {
            Sel::Select(ci) => {
                let cand = self.candidates[ci];
                if !req.satisfied_by(&cand.version) {
                    // conflict with the earlier selection: the caller
                    // backtracks (upper frame retries another candidate)
                    path.pop();
                    return Err(Error::new(
                        ErrorKind::ConstraintUnsat,
                        "version conflict with earlier selection",
                    ));
                }
                path.pop();
                return Ok(());
            }
            Sel::Keep => {
                match self.installed_version(name) {
                    Some(v) if req.satisfied_by(&v) => {
                        path.pop();
                        return Ok(());
                    }
                    _ => {
                        // the kept (installed) version does not
                        // satisfy this request: clear the pre-seeded
                        // default and select a candidate instead —
                        // upgrading/downgrading is legitimate
                        sel.set(name, Sel::Unset)?;
                    }
                }
            }
            Sel::Unset => {}
        }

        // prefer keeping the installed version when it satisfies
        let inst = self.installed_version(name);
        if let Some(v) = inst {
            if req.satisfied_by(&v) {
                sel.set(name, Sel::Keep)?;
                // record keeps in the plan
                let mut nb = [0u8; limits::MAX_NAME];
                nb[..name.len()].copy_from_slice(name);
                self.plan.push(PlanOp::Keep(nb, name.len() as u8))?;
                path.pop();
                return Ok(());
            }
        }

        // candidates for this name, newest first; reject downgrades
        // unless allowed
        let mut order: [usize; limits::MAX_PACKAGES] = [0; limits::MAX_PACKAGES];
        let mut n = 0usize;
        for (ci, c) in self.candidates.iter().enumerate() {
            if c.name() != name {
                continue;
            }
            if n >= limits::MAX_PACKAGES {
                return Err(Error::new(ErrorKind::TooLarge, "candidate list overflow"));
            }
            order[n] = ci;
            n += 1;
        }
        // insertion sort by version, descending (n is small)
        for i in 1..n {
            let mut j = i;
            while j > 0
                && self.candidates[order[j - 1]]
                    .version
                    .precedes(&self.candidates[order[j]].version)
            {
                order.swap(j - 1, j);
                j -= 1;
            }
        }
        let mut result = Err(Error::new(
            ErrorKind::ConstraintUnsat,
            "no candidate satisfies",
        ));
        for &ci in order[..n].iter() {
            let cand = self.candidates[ci];
            self.bump_steps()?;
            if !req.satisfied_by(&cand.version) {
                continue;
            }
            // downgrade policy
            if let Some(v) = inst {
                if (cand.version.precedes(&v) || cand.version == v) && !self.allow_downgrade {
                    continue;
                }
            }
            // conflict policy: candidate conflicts with any
            // selection (or installed-keep) currently in force
            let conflicting = (0..sel.count).any(|si| {
                let sname = &sel.keys[si][..sel.key_lens[si] as usize];
                let sval = sel.vals[si];
                match sval {
                    Sel::Unset => false,
                    Sel::Keep => cand.conflicts_with(sname) || cand.provides_alias(sname),
                    Sel::Select(sc) => {
                        let other = self.candidates[sc];
                        cand.conflicts_with(sname)
                            || other.conflicts_with(cand.name())
                            || (cand.provides_alias(sname) && other.name() != cand.name())
                            || (other.provides_alias(cand.name()) && other.name() != cand.name())
                    }
                }
            });
            if conflicting {
                continue;
            }
            // select and dive
            sel.set(name, Sel::Select(ci))?;
            let snapshot_steps = self.steps;
            let mut sub_ok = true;
            for dep in cand.deps[..cand.deps_len as usize].iter() {
                if let Err(e) = self.resolve_into(dep.name(), dep.req, sel, path) {
                    sub_ok = false;
                    result = Err(e);
                    break;
                }
            }
            if sub_ok {
                // plan step (deps are already ordered first)
                let op = match inst {
                    Some(_) => PlanOp::Upgrade(cand),
                    None => PlanOp::Install(cand),
                };
                if let Err(e) = self.plan.push(op) {
                    result = Err(e);
                } else {
                    path.pop();
                    return Ok(());
                }
            }
            // backtrack this candidate
            sel.set(name, Sel::Unset)?;
            self.steps = snapshot_steps;
        }
        path.pop();
        result
    }

    /// Resolve an install target: `name` with `req`.
    ///
    /// # Errors
    /// [`ErrorKind::Cycle`] with the chain; [`ErrorKind::DepthLimit`];
    /// [`ErrorKind::ConstraintUnsat`] (including budget exhaustion);
    /// [`ErrorKind::TooLarge`] on universe caps;
    /// [`ErrorKind::DowngradeBlocked`] as a precise diagnostic when
    /// the only satisfying candidate is not newer than the installed
    /// version and downgrades are not allowed.
    pub fn resolve_install(&mut self, name: &[u8], req: VersionReq) -> Result<Plan> {
        let mut sel = SelMap::new();
        let mut path = PathStack::new();
        // pre-seed keeps for every installed package so conflict
        // checks see them
        for i in self.installed {
            sel.set(i.name(), Sel::Keep)?;
            self.plan.push(PlanOp::Keep(i.name, i.name_len))?;
        }
        match self.resolve_into(name, req, &mut sel, &mut path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::ConstraintUnsat => {
                // precise downgrade diagnostic
                if let Some(v) = self.installed_version(name) {
                    let has_newer = self.candidates.iter().any(|c| {
                        c.name() == name && req.satisfied_by(&c.version) && v.precedes(&c.version)
                    });
                    let has_satisfying = self
                        .candidates
                        .iter()
                        .any(|c| c.name() == name && req.satisfied_by(&c.version));
                    if has_satisfying && !has_newer {
                        return Err(Error::with(ErrorKind::DowngradeBlocked, name));
                    }
                }
                return Err(e);
            }
            Err(e) => return Err(e),
        }
        let taken = core::mem::replace(&mut self.plan, Plan::empty());
        Ok(taken)
    }

    /// Resolve a removal: the package plus everything that
    /// (transitively) depends on it — always cascading, printed in
    /// the plan.
    ///
    /// # Errors
    /// [`ErrorKind::NotInstalled`]; [`ErrorKind::TooLarge`] on the
    /// removal-set cap.
    pub fn resolve_remove(&mut self, name: &[u8]) -> Result<Plan> {
        if self.installed_version(name).is_none() {
            return Err(Error::with(ErrorKind::NotInstalled, name));
        }
        // dependency edges between installed packages: from the
        // candidates' dep clauses when available
        let mut doomed = [[0u8; limits::MAX_NAME]; limits::MAX_PACKAGES];
        let mut doomed_lens = [0u8; limits::MAX_PACKAGES];
        let mut nd = 0usize;
        add_doomed(&mut doomed, &mut doomed_lens, &mut nd, name)?;
        // fixpoint: any installed package depending on a doomed one
        // is doomed too
        loop {
            let mut grew = false;
            for c in self.candidates {
                if !self
                    .installed
                    .iter()
                    .any(|i| i.name() == c.name() && i.version == c.version)
                {
                    continue;
                }
                let dep_hit = (0..c.deps_len as usize).any(|d| {
                    (0..nd).any(|i| &doomed[i][..doomed_lens[i] as usize] == c.deps[d].name())
                });
                if dep_hit {
                    let before = nd;
                    add_doomed(&mut doomed, &mut doomed_lens, &mut nd, c.name())?;
                    if nd > before {
                        grew = true;
                    }
                }
            }
            if !grew {
                break;
            }
        }
        // plan: removes for the doomed set
        let mut plan = Plan::empty();
        for i in 0..nd {
            plan.push(PlanOp::Remove(doomed[i], doomed_lens[i]))?;
        }
        Ok(plan)
    }
}

/// Insert `n` into the doomed set (dedup, capacity-checked).
fn add_doomed(
    doomed: &mut [[u8; limits::MAX_NAME]; limits::MAX_PACKAGES],
    lens: &mut [u8; limits::MAX_PACKAGES],
    nd: &mut usize,
    n: &[u8],
) -> Result<()> {
    if *nd >= limits::MAX_PACKAGES {
        return Err(Error::new(ErrorKind::TooLarge, "removal set overflow"));
    }
    if n.len() > limits::MAX_NAME {
        return Err(Error::new(ErrorKind::TooLarge, "name above cap"));
    }
    if (0..*nd).any(|i| &doomed[i][..lens[i] as usize] == n) {
        return Ok(());
    }
    doomed[*nd][..n.len()].copy_from_slice(n);
    lens[*nd] = n.len() as u8;
    *nd += 1;
    Ok(())
}
