use std::fs::File;
use std::io::ErrorKind;
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::sync::mpsc;
#[cfg(feature = "libseccomp")]
use std::path::PathBuf;

use nix::errno::Errno;
use nix::sched::CloneFlags;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, close, fork, pipe, read as nix_read, write as nix_write};
use oci_spec::runtime::LinuxIdMapping;

use crate::process::args::ContainerArgs;
use crate::process::fork::{self, CloneCb};
use crate::process::intel_rdt::setup_intel_rdt;
use crate::process::message::{Message, MountMsg};
use crate::process::{channel, container_intermediate_process};
#[cfg(feature = "libseccomp")]
use crate::process::seccomp_listener;
#[cfg(feature = "libseccomp")]
use crate::seccomp;
use crate::syscall::syscall::SyscallType;
use crate::syscall::{Syscall, SyscallError, linux};
use crate::user_ns::UserNamespaceConfig;
use crate::utils;

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error(transparent)]
    Channel(#[from] channel::ChannelError),
    #[error("failed to write deny to setgroups")]
    SetGroupsDeny(#[source] std::io::Error),
    #[error(transparent)]
    UserNamespace(#[from] crate::user_ns::UserNamespaceError),
    #[error("container state is required")]
    ContainerStateRequired,
    #[error("failed to wait for intermediate process")]
    WaitIntermediateProcess(#[source] nix::Error),
    #[error(transparent)]
    IntelRdt(#[from] crate::process::intel_rdt::IntelRdtError),
    #[error("failed to create intermediate process")]
    IntermediateProcessFailed(#[source] fork::CloneError),
    #[error("failed seccomp listener")]
    #[cfg(feature = "libseccomp")]
    SeccompListener(#[from] crate::process::seccomp_listener::SeccompListenerError),
    #[error("failed syscall")]
    SyscallOther(#[source] SyscallError),
    #[error("mount request failed: {0}")]
    MountRequest(String),
}

type Result<T> = std::result::Result<T, ProcessError>;

struct MountWorkerRequest {
    msg: MountMsg,
    response: mpsc::Sender<std::result::Result<OwnedFd, String>>,
}

pub fn container_main_process(container_args: &ContainerArgs) -> Result<(Pid, bool)> {
    // We use a set of channels to communicate between parent and child process.
    // Each channel is uni-directional. Because we will pass these channel to
    // cloned process, we have to be deligent about closing any unused channel.
    // At minimum, we have to close down any unused senders. The corresponding
    // receivers will be cleaned up once the senders are closed down.
    let (mut main_sender, mut main_receiver) = channel::main_channel()?;
    let mut inter_chan = channel::intermediate_channel()?;
    let mut init_chan = channel::init_channel()?;
    let syscall = container_args.syscall.create_syscall();

    let cb: CloneCb = {
        Box::new(|| {
            if let Err(ret) = prctl::set_name("youki:[1:INTER]") {
                tracing::error!(?ret, "failed to set name for child process");
                return ret;
            }

            match container_intermediate_process::container_intermediate_process(
                container_args,
                &mut inter_chan,
                &mut init_chan,
                &mut main_sender,
            ) {
                Ok(_) => 0,
                Err(err) => {
                    tracing::error!("failed to run intermediate process {}", err);
                    match main_sender.send_error(err.to_string()) {
                        Ok(_) => {}
                        Err(e) => {
                            tracing::error!(
                                "error in sending intermediate error message {} to main: {}",
                                err,
                                e
                            )
                        }
                    }
                    -1
                }
            }
        })
    };

    let container_clone_fn = if container_args.as_sibling {
        fork::container_clone_sibling
    } else {
        fork::container_clone
    };

    let intermediate_pid = container_clone_fn(cb).map_err(|err| {
        tracing::error!("failed to fork intermediate process: {}", err);
        ProcessError::IntermediateProcessFailed(err)
    })?;

    // Close down unused fds. The corresponding fds are duplicated to the
    // child process during clone.
    main_sender.close().map_err(|err| {
        tracing::error!("failed to close unused sender: {}", err);
        err
    })?;

    let (mut inter_sender, inter_receiver) = inter_chan;
    let (mut init_sender, init_receiver) = init_chan;

    // If creating a container with new user namespace, the intermediate process will ask
    // the main process to set up uid and gid mapping, once the intermediate
    // process enters into a new user namespace.
    if let Some(config) = &container_args.user_ns_config {
        main_receiver.wait_for_mapping_request()?;
        setup_mapping(config, intermediate_pid)?;
        inter_sender.mapping_written()?;
    }

    // At this point, we don't need to send any message to intermediate process anymore,
    // so we want to close this sender at the earliest point.
    inter_sender.close().map_err(|err| {
        tracing::error!("failed to close unused intermediate sender: {}", err);
        err
    })?;

    // The intermediate process will send the init pid once it forks the init
    // process.  The intermediate process should exit after this point.
    let init_pid = main_receiver.wait_for_intermediate_ready()?;
    let mut need_to_clean_up_intel_rdt_subdirectory = false;
    let rootless = utils::rootless_required(syscall.as_ref()).map_err(|err| {
        ProcessError::MountRequest(format!("failed to detect rootless mode: {err}"))
    })?;
    let mount_worker_tx = start_mount_worker(init_pid, container_args.syscall);
    #[cfg(feature = "libseccomp")]
    let mut seccomp_state: Option<(PathBuf, Vec<u8>)> = None;

    if let Some(linux) = container_args.spec.linux() {
        #[cfg(feature = "libseccomp")]
        if let Some(seccomp) = linux.seccomp() {
            if seccomp::is_notify(seccomp) {
                let state = crate::container::ContainerProcessState {
                    oci_version: container_args.spec.version().to_string(),
                    // runc hardcode the `seccompFd` name for fds.
                    fds: vec![String::from("seccompFd")],
                    pid: init_pid.as_raw(),
                    metadata: seccomp.listener_metadata().to_owned().unwrap_or_default(),
                    state: container_args
                        .container
                        .as_ref()
                        .ok_or(ProcessError::ContainerStateRequired)?
                        .state
                        .clone(),
                };
                let listener_path = seccomp
                    .listener_path()
                    .as_ref()
                    .ok_or(seccomp_listener::SeccompListenerError::MissingListenerPath)?;
                let encoded_state = serde_json::to_vec(&state)
                    .map_err(seccomp_listener::SeccompListenerError::EncodeState)?;
                seccomp_state = Some((listener_path.to_path_buf(), encoded_state));
            }
        }

        if let Some(intel_rdt) = linux.intel_rdt() {
            let container_id = container_args
                .container
                .as_ref()
                .map(|container| container.id());
            need_to_clean_up_intel_rdt_subdirectory =
                setup_intel_rdt(container_id, &init_pid, intel_rdt)?;
        }
    }

    loop {
        let (msg, fds) = main_receiver.recv_message_with_fds()?;
        match msg {
            Message::InitReady => break,
            Message::MountFdPlease(req) => {
                if rootless {
                    let msg = "idmapped mounts are not supported for rootless".to_string();
                    let _ = init_sender.send_mount_fd_error(msg.clone());
                    return Err(ProcessError::MountRequest(msg));
                }
                let (resp_tx, resp_rx) = mpsc::channel();
                mount_worker_tx
                    .send(MountWorkerRequest {
                        msg: req,
                        response: resp_tx,
                    })
                    .map_err(|err| {
                        ProcessError::MountRequest(format!(
                            "failed to send mount request to worker: {err}"
                        ))
                    })?;
                let response = resp_rx.recv().map_err(|err| {
                    ProcessError::MountRequest(format!(
                        "failed to receive mount response from worker: {err}"
                    ))
                })?;
                match response {
                    Ok(fd) => init_sender.send_mount_fd_reply(fd)?,
                    Err(err) => {
                        let _ = init_sender.send_mount_fd_error(err.clone());
                        return Err(ProcessError::MountRequest(err));
                    }
                }
            }
            Message::SeccompNotify => {
                #[cfg(feature = "libseccomp")]
                {
                    let seccomp_fd = match fds {
                        Some([fd]) => fd,
                        _ => {
                            return Err(ProcessError::Channel(
                                channel::ChannelError::MissingSeccompFds,
                            ));
                        }
                    };
                    let (listener_path, encoded_state) = seccomp_state.as_ref().ok_or(
                        seccomp_listener::SeccompListenerError::MissingListenerPath,
                    )?;
                    seccomp_listener::sync_seccomp_send_msg(
                        listener_path,
                        encoded_state.as_slice(),
                        seccomp_fd,
                    )?;
                    init_sender.seccomp_notify_done()?;
                    let _ = close(seccomp_fd);
                }
                #[cfg(not(feature = "libseccomp"))]
                {
                    return Err(ProcessError::Channel(
                        channel::ChannelError::UnexpectedMessage {
                            expected: Message::InitReady,
                            received: Message::SeccompNotify,
                        },
                    ));
                }
            }
            Message::ExecFailed(err) => {
                return Err(ProcessError::Channel(channel::ChannelError::ExecError(err)));
            }
            Message::OtherError(err) => {
                return Err(ProcessError::Channel(channel::ChannelError::OtherError(err)));
            }
            msg => {
                return Err(ProcessError::Channel(
                    channel::ChannelError::UnexpectedMessage {
                        expected: Message::InitReady,
                        received: msg,
                    },
                ));
            }
        }
    }

    drop(mount_worker_tx);

    // We don't need to send anything to the init process after this point, so
    // close the sender.
    init_sender.close().map_err(|err| {
        tracing::error!("failed to close unused init sender: {}", err);
        err
    })?;

    tracing::debug!("init pid is {:?}", init_pid);

    // Close the receiver ends to avoid leaking file descriptors.

    inter_receiver.close().map_err(|err| {
        tracing::error!("failed to close intermediate process receiver: {}", err);
        err
    })?;

    init_receiver.close().map_err(|err| {
        tracing::error!("failed to close init process receiver: {}", err);
        err
    })?;

    main_receiver.close().map_err(|err| {
        tracing::error!("failed to close main process receiver: {}", err);
        err
    })?;

    // Before the main process returns, we want to make sure the intermediate
    // process is exit and reaped. By this point, the intermediate process
    // should already exited successfully. If intermediate process errors out,
    // the `init_ready` will not be sent.
    match waitpid(intermediate_pid, None) {
        Ok(WaitStatus::Exited(_, 0)) => (),
        Ok(WaitStatus::Exited(_, s)) => {
            tracing::warn!("intermediate process failed with exit status: {s}");
        }
        Ok(WaitStatus::Signaled(_, sig, _)) => {
            tracing::warn!("intermediate process killed with signal: {sig}")
        }
        Ok(_) => (),
        Err(nix::errno::Errno::ECHILD) => {
            // This is safe because intermediate_process and main_process check if the process is
            // finished by piping instead of exit code.
            tracing::warn!("intermediate process already reaped");
        }
        Err(err) => return Err(ProcessError::WaitIntermediateProcess(err)),
    };

    Ok((init_pid, need_to_clean_up_intel_rdt_subdirectory))
}

fn idmapped_error_message(err: &ProcessError) -> String {
    match err {
        ProcessError::SyscallOther(SyscallError::Nix(Errno::ENOSYS)) => {
            "idmapped mounts require open_tree/mount_setattr support (Linux 5.12+)".to_string()
        }
        _ => err.to_string(),
    }
}

fn write_id_mapping_file(pid: Pid, file_name: &str, mappings: &[LinuxIdMapping]) -> Result<()> {
    if mappings.is_empty() {
        return Err(ProcessError::MountRequest(format!(
            "{file_name} mappings are empty"
        )));
    }
    let mut content = String::new();
    for mapping in mappings {
        content.push_str(&format!(
            "{} {} {}\n",
            mapping.container_id(),
            mapping.host_id(),
            mapping.size()
        ));
    }
    let path = format!("/proc/{}/{}", pid.as_raw(), file_name);
    std::fs::write(&path, content).map_err(|err| {
        tracing::error!(?err, ?path, "failed to write id mapping");
        ProcessError::MountRequest(format!("failed to write {file_name}: {err}"))
    })?;
    Ok(())
}

fn create_userns_fd(
    uid_mappings: &[LinuxIdMapping],
    gid_mappings: &[LinuxIdMapping],
) -> Result<OwnedFd> {
    let (read_fd, write_fd) = pipe().map_err(|err| {
        ProcessError::MountRequest(format!("failed to create userns pipe: {err}"))
    })?;
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let _ = close(write_fd);
            if let Err(err) = nix::sched::unshare(CloneFlags::CLONE_NEWUSER) {
                tracing::error!(?err, "failed to unshare user namespace");
                std::process::exit(1);
            }

            let mut buf = [0u8; 1];
            let _ = nix_read(read_fd, &mut buf);
            std::process::exit(0);
        }
        Ok(ForkResult::Parent { child }) => {
            close(read_fd).map_err(|err| {
                ProcessError::MountRequest(format!("failed to close userns pipe: {err}"))
            })?;
            let result = (|| -> Result<OwnedFd> {
                let setgroups_path = format!("/proc/{}/setgroups", child.as_raw());
                if let Err(err) = std::fs::write(&setgroups_path, "deny") {
                    if err.kind() != ErrorKind::NotFound {
                        return Err(ProcessError::SetGroupsDeny(err));
                    }
                }

                write_id_mapping_file(child, "uid_map", uid_mappings)?;
                write_id_mapping_file(child, "gid_map", gid_mappings)?;

                let userns_path = format!("/proc/{}/ns/user", child.as_raw());
                let fd = File::open(&userns_path).map_err(|err| {
                    ProcessError::MountRequest(format!("failed to open user namespace: {err}"))
                })?;
                Ok(fd.into())
            })();
            let _ = nix_write(write_fd, &[1]);
            let _ = close(write_fd);
            let _ = waitpid(child, None);
            result
        }
        Err(err) => Err(ProcessError::MountRequest(format!(
            "failed to fork userns helper: {err}"
        ))),
    }
}

fn start_mount_worker(init_pid: Pid, syscall_type: SyscallType) -> mpsc::Sender<MountWorkerRequest> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let syscall = syscall_type.create_syscall();
        let mut mountns_error: Option<ProcessError> = None;
        let mut mountns_ready = false;

        for req in rx {
            if !mountns_ready && mountns_error.is_none() {
                let result = (|| -> Result<()> {
                    let target_mnt = File::open(format!("/proc/{}/ns/mnt", init_pid.as_raw()))
                        .map_err(|err| {
                            ProcessError::MountRequest(format!(
                                "failed to open init mount namespace: {err}"
                            ))
                        })?;
                    syscall
                        .set_ns(target_mnt.as_raw_fd(), CloneFlags::CLONE_NEWNS)
                        .map_err(ProcessError::SyscallOther)?;
                    Ok(())
                })();
                match result {
                    Ok(()) => mountns_ready = true,
                    Err(err) => mountns_error = Some(err),
                }
            }

            let response = match &mountns_error {
                Some(err) => Err(idmapped_error_message(err)),
                None => mount_idmapped_fd(syscall.as_ref(), &req.msg)
                    .map_err(|err| idmapped_error_message(&err)),
            };
            let _ = req.response.send(response);
        }
    });

    tx
}

fn mount_idmapped_fd(syscall: &dyn Syscall, req: &MountMsg) -> Result<OwnedFd> {
    let idmap = req.idmap.as_ref().ok_or_else(|| {
        ProcessError::MountRequest("idmapped mount request missing mappings".to_string())
    })?;
    if !req.is_bind {
        return Err(ProcessError::MountRequest(
            "idmapped mount requires bind source".to_string(),
        ));
    }

    let userns_fd = create_userns_fd(&idmap.uid_mappings, &idmap.gid_mappings)?;
    let mut open_flags = linux::OPEN_TREE_CLONE | linux::OPEN_TREE_CLOEXEC;
    if idmap.recursive {
        open_flags |= linux::AT_RECURSIVE;
    }
    let mount_fd = syscall
        .open_tree(libc::AT_FDCWD, Path::new(&req.source), open_flags)
        .map_err(ProcessError::SyscallOther)?;

    let mut setattr_flags = linux::AT_EMPTY_PATH;
    if idmap.recursive {
        setattr_flags |= linux::AT_RECURSIVE;
    }
    let mount_attr = linux::MountAttr {
        attr_set: linux::MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: 0,
        userns_fd: userns_fd.as_raw_fd() as u64,
    };
    syscall
        .mount_setattr(
            mount_fd.as_raw_fd(),
            Path::new(""),
            setattr_flags,
            &mount_attr,
            mem::size_of::<linux::MountAttr>(),
        )
        .map_err(ProcessError::SyscallOther)?;
    Ok(mount_fd)
}

fn setup_mapping(config: &UserNamespaceConfig, pid: Pid) -> Result<()> {
    tracing::debug!("write mapping for pid {:?}", pid);
    if !config.privileged {
        // The main process is running as an unprivileged user and cannot write the mapping
        // until "deny" has been written to setgroups. See CVE-2014-8989.
        std::fs::write(format!("/proc/{pid}/setgroups"), "deny")
            .map_err(ProcessError::SetGroupsDeny)?;
    }

    config.write_uid_mapping(pid).map_err(|err| {
        tracing::error!("failed to write uid mapping for pid {:?}: {}", pid, err);
        err
    })?;
    config.write_gid_mapping(pid).map_err(|err| {
        tracing::error!("failed to write gid mapping for pid {:?}: {}", pid, err);
        err
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    use nix::sched::{CloneFlags, unshare};
    use nix::unistd::{self, getgid, getuid};
    use oci_spec::runtime::LinuxIdMappingBuilder;
    use serial_test::serial;

    use super::*;
    use crate::process::channel::{intermediate_channel, main_channel};
    use crate::user_ns::UserNamespaceIDMapper;

    #[test]
    #[serial]
    fn setup_uid_mapping_should_succeed() -> Result<()> {
        let uid_mapping = LinuxIdMappingBuilder::default()
            .host_id(getuid())
            .container_id(0u32)
            .size(1u32)
            .build()?;
        let uid_mappings = vec![uid_mapping];
        let tmp = tempfile::tempdir()?;
        let id_mapper = UserNamespaceIDMapper::new_test(tmp.path().to_path_buf());
        let ns_config = UserNamespaceConfig {
            uid_mappings: Some(uid_mappings),
            privileged: true,
            id_mapper: id_mapper.clone(),
            ..Default::default()
        };
        let (mut parent_sender, mut parent_receiver) = main_channel()?;
        let (mut child_sender, mut child_receiver) = intermediate_channel()?;
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                parent_receiver.wait_for_mapping_request()?;
                parent_receiver.close()?;

                // In test, we fake the uid path in /proc/{pid}/uid_map, so we
                // need to ensure the path exists before we write the mapping.
                // The path requires the pid we use, so we can only do do after
                // obtaining the child pid here.
                id_mapper.ensure_uid_path(&child)?;
                setup_mapping(&ns_config, child)?;
                let line = fs::read_to_string(id_mapper.get_uid_path(&child))?;
                let split_lines = line.split_whitespace();
                for (act, expect) in split_lines.zip([
                    uid_mapping.container_id().to_string(),
                    uid_mapping.host_id().to_string(),
                    uid_mapping.size().to_string(),
                ]) {
                    assert_eq!(act, expect);
                }
                child_sender.mapping_written()?;
                child_sender.close()?;
            }
            unistd::ForkResult::Child => {
                prctl::set_dumpable(true).unwrap();
                unshare(CloneFlags::CLONE_NEWUSER)?;
                parent_sender.identifier_mapping_request()?;
                parent_sender.close()?;
                child_receiver.wait_for_mapping_ack()?;
                child_receiver.close()?;
                std::process::exit(0);
            }
        }
        Ok(())
    }

    #[test]
    #[serial]
    fn setup_gid_mapping_should_succeed() -> Result<()> {
        let gid_mapping = LinuxIdMappingBuilder::default()
            .host_id(getgid())
            .container_id(0u32)
            .size(1u32)
            .build()?;
        let gid_mappings = vec![gid_mapping];
        let tmp = tempfile::tempdir()?;
        let id_mapper = UserNamespaceIDMapper::new_test(tmp.path().to_path_buf());
        let ns_config = UserNamespaceConfig {
            gid_mappings: Some(gid_mappings),
            id_mapper: id_mapper.clone(),
            ..Default::default()
        };
        let (mut parent_sender, mut parent_receiver) = main_channel()?;
        let (mut child_sender, mut child_receiver) = intermediate_channel()?;
        match unsafe { unistd::fork()? } {
            unistd::ForkResult::Parent { child } => {
                parent_receiver.wait_for_mapping_request()?;
                parent_receiver.close()?;

                // In test, we fake the gid path in /proc/{pid}/gid_map, so we
                // need to ensure the path exists before we write the mapping.
                // The path requires the pid we use, so we can only do do after
                // obtaining the child pid here.
                id_mapper.ensure_gid_path(&child)?;
                setup_mapping(&ns_config, child)?;
                let line = fs::read_to_string(id_mapper.get_gid_path(&child))?;
                let split_lines = line.split_whitespace();
                for (act, expect) in split_lines.zip([
                    gid_mapping.container_id().to_string(),
                    gid_mapping.host_id().to_string(),
                    gid_mapping.size().to_string(),
                ]) {
                    assert_eq!(act, expect);
                }
                assert_eq!(
                    fs::read_to_string(format!("/proc/{}/setgroups", child.as_raw()))?,
                    "deny\n",
                );
                child_sender.mapping_written()?;
                child_sender.close()?;
            }
            unistd::ForkResult::Child => {
                prctl::set_dumpable(true).unwrap();
                unshare(CloneFlags::CLONE_NEWUSER)?;
                parent_sender.identifier_mapping_request()?;
                parent_sender.close()?;
                child_receiver.wait_for_mapping_ack()?;
                child_receiver.close()?;
                std::process::exit(0);
            }
        }
        Ok(())
    }
}
