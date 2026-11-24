/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `--pin`: best effort, the server pins itself to the first CPU it may run on and the client to
//! the first one on another physical core of the same package, so the two run on distinct cores
//! when started with the same affinity mask, as mvfst's tperf does.

use std::fs;
use std::io;
use std::mem;
use std::path::Path;

use crate::flags::Mode;

/// Where a CPU sits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Topology {
    /// The physical package (socket).
    pub(crate) package: u32,
    /// The core within the package; SMT siblings share it.
    pub(crate) core: u32,
}

/// Returns the CPU that `mode` pins to among `allowed`, which is in ascending order, given each
/// CPU's topology where known.
pub(crate) fn select_cpu(
    mode: Mode,
    allowed: &[usize],
    topology: impl Fn(usize) -> Option<Topology>,
) -> Option<usize> {
    let &server = allowed.first()?;
    if mode == Mode::Server {
        return Some(server);
    }
    let another_core = topology(server).and_then(|ours| {
        allowed.iter().copied().find(|&cpu| {
            topology(cpu)
                .is_some_and(|theirs| theirs.package == ours.package && theirs.core != ours.core)
        })
    });
    Some(another_core.or(allowed.get(1).copied()).unwrap_or(server))
}

/// Reads the topology of `cpu` from the sysfs CPU directory `root` ([`SYSFS_CPUS`] on a live
/// system), or `None` if its files are missing or do not hold numbers.
pub(crate) fn topology_in(root: &Path, cpu: usize) -> Option<Topology> {
    let dir = root.join(format!("cpu{cpu}/topology"));
    let read = |name| fs::read_to_string(dir.join(name)).ok()?.trim().parse().ok();
    Some(Topology {
        package: read("physical_package_id")?,
        core: read("core_id")?,
    })
}

/// Pins the calling thread, and the threads it starts later, to the CPU [`select_cpu`] picks for
/// `mode` among those it may run on now, and returns that CPU.
pub(crate) fn pin(mode: Mode) -> io::Result<usize> {
    let root = Path::new(SYSFS_CPUS);
    let cpu = select_cpu(mode, &allowed_cpus()?, |cpu| topology_in(root, cpu))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no CPU to run on"))?;
    pin_to(cpu)?;
    Ok(cpu)
}

/// The sysfs CPU directory [`topology_in`] reads on a live system.
const SYSFS_CPUS: &str = "/sys/devices/system/cpu";

/// The CPUs a `cpu_set_t` holds.
const SET_SIZE: usize = libc::CPU_SETSIZE as usize;

/// Returns the CPUs the calling thread may run on, in ascending order.
#[expect(unsafe_code, reason = "sched_getaffinity(2) through libc")]
pub(crate) fn allowed_cpus() -> io::Result<Vec<usize>> {
    // SAFETY: a `cpu_set_t` is a bit array, for which all zeros is valid.
    let mut set: libc::cpu_set_t = unsafe { mem::zeroed() };
    // SAFETY: `set` is a writable `cpu_set_t` of the size passed; pid 0 is the calling thread.
    if unsafe { libc::sched_getaffinity(0, size_of_val(&set), &mut set) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((0..SET_SIZE)
        // SAFETY: every index is below `CPU_SETSIZE`, so within `set`.
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
        .collect())
}

/// Lets the calling thread, and the threads it starts later, run only on `cpu`.
#[expect(unsafe_code, reason = "sched_setaffinity(2) through libc")]
pub(crate) fn pin_to(cpu: usize) -> io::Result<()> {
    if cpu >= SET_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("CPU {cpu} is beyond a cpu_set_t"),
        ));
    }
    // SAFETY: a `cpu_set_t` is a bit array, for which all zeros is valid.
    let mut set: libc::cpu_set_t = unsafe { mem::zeroed() };
    // SAFETY: `cpu` is below `CPU_SETSIZE`, so within `set`.
    unsafe { libc::CPU_SET(cpu, &mut set) };
    // SAFETY: `set` is a `cpu_set_t` of the size passed; pid 0 is the calling thread.
    if unsafe { libc::sched_setaffinity(0, size_of_val(&set), &set) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns `cpu`'s topology in a layout of SMT sibling pairs 2k and 2k + 1, all in one package.
    fn siblings_in_pairs(cpu: usize) -> Option<Topology> {
        Some(Topology {
            package: 0,
            core: (cpu / 2) as u32,
        })
    }

    #[test]
    fn the_server_takes_the_first_cpu_and_the_client_another_core() {
        let allowed = [8, 9, 10, 11];
        assert_eq!(
            select_cpu(Mode::Server, &allowed, siblings_in_pairs),
            Some(8)
        );
        assert_eq!(
            select_cpu(Mode::Client, &allowed, siblings_in_pairs),
            Some(10),
            "not 9, the server's SMT sibling"
        );
        assert_eq!(
            select_cpu(Mode::Client, &allowed, |_| None),
            Some(9),
            "the second CPU when the topology is unknown"
        );
        let other_package = |cpu| {
            Some(Topology {
                package: u32::from(cpu == 2),
                core: 0,
            })
        };
        assert_eq!(
            select_cpu(Mode::Client, &[0, 1, 2], other_package),
            Some(1),
            "never a core of another package"
        );
        assert_eq!(select_cpu(Mode::Client, &[5], siblings_in_pairs), Some(5));
        assert_eq!(select_cpu(Mode::Server, &[], siblings_in_pairs), None);
    }

    #[test]
    fn the_topology_comes_from_the_sysfs_files() {
        let root =
            std::env::temp_dir().join(format!("mvfstr-tperf-topology-{}", std::process::id()));
        let cpu = |n: usize, package: &str, core: &str| {
            let dir = root.join(format!("cpu{n}/topology"));
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("physical_package_id"), package).unwrap();
            fs::write(dir.join("core_id"), core).unwrap();
        };
        cpu(3, "0\n", "17\n");
        cpu(4, "1\n", "core\n");
        assert_eq!(
            topology_in(&root, 3),
            Some(Topology {
                package: 0,
                core: 17,
            })
        );
        assert_eq!(topology_in(&root, 4), None, "a value that is not a number");
        assert_eq!(topology_in(&root, 5), None, "no such CPU");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_pinned_thread_may_run_only_on_its_cpu() {
        std::thread::spawn(|| {
            let allowed = allowed_cpus().unwrap();
            assert!(!allowed.is_empty());
            assert!(allowed.is_sorted());
            let last = *allowed.last().unwrap();
            pin_to(last).unwrap();
            assert_eq!(allowed_cpus().unwrap(), [last]);
            let error = pin_to(libc::CPU_SETSIZE as usize).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(
                allowed_cpus().unwrap(),
                [last],
                "a refused pin changes nothing"
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    fn each_side_pins_itself_to_the_cpu_it_selects() {
        for mode in [Mode::Server, Mode::Client] {
            std::thread::spawn(move || {
                let allowed = allowed_cpus().unwrap();
                let expected = select_cpu(mode, &allowed, |cpu| {
                    topology_in(Path::new(SYSFS_CPUS), cpu)
                })
                .unwrap();
                assert_eq!(pin(mode).unwrap(), expected, "{mode:?}");
                assert_eq!(allowed_cpus().unwrap(), [expected], "{mode:?}");
            })
            .join()
            .unwrap();
        }
    }
}
