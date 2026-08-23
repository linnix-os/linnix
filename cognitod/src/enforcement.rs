use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

mod safety;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ActionType {
    KillProcess { pid: u32, signal: i32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time_ticks: u64,
    pub stat_comm: String,
    pub cgroups: Vec<ProcessCgroupIdentity>,
    pub pid_namespaces: Vec<ProcessNamespaceIdentity>,
    pub captured_at_ms: u64,
}

impl ProcessIdentity {
    fn same_process_as(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.start_time_ticks == other.start_time_ticks
            && self.stat_comm == other.stat_comm
            && self.cgroups == other.cgroups
            && self.pid_namespaces == other.pid_namespaces
    }

    #[cfg(test)]
    fn for_test(pid: u32) -> Self {
        Self {
            pid,
            start_time_ticks: 42,
            stat_comm: "test-process".to_string(),
            cgroups: vec![ProcessCgroupIdentity {
                hierarchy: 0,
                controllers: vec![],
                pathname: "/test.slice".to_string(),
            }],
            pid_namespaces: vec![ProcessNamespaceIdentity {
                namespace_type: "pid".to_string(),
                device_id: 1,
                inode: 2,
            }],
            captured_at_ms: current_epoch_millis(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProcessCgroupIdentity {
    pub hierarchy: u32,
    pub controllers: Vec<String>,
    pub pathname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProcessNamespaceIdentity {
    pub namespace_type: String,
    pub device_id: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessIdentityError {
    Missing {
        pid: u32,
    },
    Unreadable {
        pid: u32,
        detail: String,
    },
    Mismatch {
        pid: u32,
        expected: Box<ProcessIdentity>,
        actual: Box<ProcessIdentity>,
    },
    Expired {
        pid: u32,
        expires_at: u64,
        now: u64,
    },
}

impl fmt::Display for ProcessIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { pid } => write!(f, "process {pid} is missing"),
            Self::Unreadable { pid, detail } => {
                write!(f, "process {pid} identity is unreadable: {detail}")
            }
            Self::Mismatch { pid, .. } => {
                write!(f, "process {pid} identity changed before kill")
            }
            Self::Expired {
                pid,
                expires_at,
                now,
            } => write!(
                f,
                "process {pid} identity expired before kill: expires_at={expires_at} now={now}"
            ),
        }
    }
}

impl std::error::Error for ProcessIdentityError {}

pub trait ProcessIdentityProvider: Send + Sync {
    fn identity_for_pid(&self, pid: u32) -> Result<ProcessIdentity, ProcessIdentityError>;
}

#[derive(Debug, Default)]
struct ProcProcessIdentityProvider;

impl ProcProcessIdentityProvider {
    fn map_proc_error(pid: u32, context: &str, err: procfs::ProcError) -> ProcessIdentityError {
        match err {
            procfs::ProcError::NotFound(_) => ProcessIdentityError::Missing { pid },
            other => ProcessIdentityError::Unreadable {
                pid,
                detail: format!("{context}: {other}"),
            },
        }
    }
}

impl ProcessIdentityProvider for ProcProcessIdentityProvider {
    fn identity_for_pid(&self, pid: u32) -> Result<ProcessIdentity, ProcessIdentityError> {
        use procfs::process::Process;

        let process = Process::new(pid as i32)
            .map_err(|err| Self::map_proc_error(pid, "open /proc entry", err))?;
        let stat = process
            .stat()
            .map_err(|err| Self::map_proc_error(pid, "read stat", err))?;

        if matches!(stat.state, 'Z' | 'X') {
            return Err(ProcessIdentityError::Missing { pid });
        }

        let mut cgroups: Vec<ProcessCgroupIdentity> = process
            .cgroups()
            .map_err(|err| Self::map_proc_error(pid, "read cgroup", err))?
            .into_iter()
            .map(|group| {
                let mut controllers = group.controllers;
                controllers.sort();
                ProcessCgroupIdentity {
                    hierarchy: group.hierarchy,
                    controllers,
                    pathname: group.pathname,
                }
            })
            .collect();
        cgroups.sort();

        let mut pid_namespaces: Vec<ProcessNamespaceIdentity> = process
            .namespaces()
            .map_err(|err| Self::map_proc_error(pid, "read namespaces", err))?
            .0
            .into_iter()
            .filter_map(|(namespace_type, namespace)| {
                let namespace_type = namespace_type.to_string_lossy().into_owned();
                (namespace_type == "pid" || namespace_type == "pid_for_children").then_some(
                    ProcessNamespaceIdentity {
                        namespace_type,
                        device_id: namespace.device_id,
                        inode: namespace.identifier,
                    },
                )
            })
            .collect();
        pid_namespaces.sort();

        if !pid_namespaces
            .iter()
            .any(|namespace| namespace.namespace_type == "pid")
        {
            return Err(ProcessIdentityError::Unreadable {
                pid,
                detail: "missing pid namespace identity".to_string(),
            });
        }

        Ok(ProcessIdentity {
            pid,
            start_time_ticks: stat.starttime,
            stat_comm: stat.comm,
            cgroups,
            pid_namespaces,
            captured_at_ms: current_epoch_millis(),
        })
    }
}

pub trait SignalHandle: Send {
    fn send_signal(&self, signal: i32) -> Result<(), std::io::Error>;
}

pub trait SignalSender: Send + Sync {
    fn open_handle(&self, pid: u32) -> Result<Box<dyn SignalHandle>, std::io::Error>;
}

#[derive(Debug, Default)]
struct PidfdSignalSender;

#[derive(Debug)]
struct PidfdSignalHandle {
    pidfd: OwnedFd,
}

impl SignalSender for PidfdSignalSender {
    fn open_handle(&self, pid: u32) -> Result<Box<dyn SignalHandle>, std::io::Error> {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
            Ok(Box::new(PidfdSignalHandle { pidfd }))
        }
    }
}

impl SignalHandle for PidfdSignalHandle {
    fn send_signal(&self, signal: i32) -> Result<(), std::io::Error> {
        let sent = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if sent == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
struct TestProcessIdentityProvider;

#[cfg(test)]
impl ProcessIdentityProvider for TestProcessIdentityProvider {
    fn identity_for_pid(&self, pid: u32) -> Result<ProcessIdentity, ProcessIdentityError> {
        Ok(ProcessIdentity::for_test(pid))
    }
}

#[cfg(test)]
#[derive(Debug)]
struct TestSignalSender;

#[cfg(test)]
impl SignalSender for TestSignalSender {
    fn open_handle(&self, _pid: u32) -> Result<Box<dyn SignalHandle>, std::io::Error> {
        Ok(Box::new(TestSignalHandle))
    }
}

#[cfg(test)]
#[derive(Debug)]
struct TestSignalHandle;

#[cfg(test)]
impl SignalHandle for TestSignalHandle {
    fn send_signal(&self, _signal: i32) -> Result<(), std::io::Error> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ActionStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Executed,
    /// The executor tried and the syscall failed — the process was already
    /// gone, or the signal was refused.
    ///
    /// Distinct from `Rejected`, which is an operator's decision, and terminal
    /// so the executor does not retry: a pid that has exited can be reused,
    /// and retrying would eventually kill an unrelated process.
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnforcementAction {
    pub id: String,
    pub action: ActionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_identity: Option<ProcessIdentity>,
    pub reason: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    pub status: ActionStatus,
    pub created_at: u64,
    pub expires_at: u64,
    /// When the executor actually carried the action out, in epoch
    /// milliseconds.
    ///
    /// Recovery has to be timed from the kill, not from whenever the watcher
    /// got around to noticing it: the insert and the polling gap in between
    /// would otherwise be silently dropped, and pressure that had already
    /// fallen would be stored as a 0ms recovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<u64>,
}

pub struct EnforcementQueue {
    /// Count of actions that have actually executed, for detecting overlap.
    executions: AtomicU64,
    next_id: AtomicU64,
    actions: RwLock<HashMap<String, EnforcementAction>>,
    identity_provider: Arc<dyn ProcessIdentityProvider>,
    signal_sender: Arc<dyn SignalSender>,
    ttl_secs: u64,
}

impl EnforcementQueue {
    pub fn new(ttl_secs: u64) -> Self {
        Self::new_with_components(
            ttl_secs,
            Arc::new(ProcProcessIdentityProvider),
            Arc::new(PidfdSignalSender),
        )
    }

    #[doc(hidden)]
    pub fn new_with_components(
        ttl_secs: u64,
        identity_provider: Arc<dyn ProcessIdentityProvider>,
        signal_sender: Arc<dyn SignalSender>,
    ) -> Self {
        Self {
            executions: AtomicU64::new(0),
            next_id: AtomicU64::new(1),
            actions: RwLock::new(HashMap::new()),
            identity_provider,
            signal_sender,
            ttl_secs,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(ttl_secs: u64) -> Self {
        Self::new_with_components(
            ttl_secs,
            Arc::new(TestProcessIdentityProvider),
            Arc::new(TestSignalSender),
        )
    }

    #[cfg(test)]
    fn new_for_test_with_components(
        ttl_secs: u64,
        identity_provider: Arc<dyn ProcessIdentityProvider>,
        signal_sender: Arc<dyn SignalSender>,
    ) -> Self {
        Self::new_with_components(ttl_secs, identity_provider, signal_sender)
    }

    pub async fn propose(
        &self,
        action: ActionType,
        reason: String,
        source: String,
        confidence: Option<f64>,
    ) -> Result<String, String> {
        self.propose_internal(action, reason, source, confidence, false)
            .await
    }

    /// Propose an action with optional auto-approval
    ///
    /// If auto_approve=true, the action is immediately approved by "circuit_breaker"
    /// after safety checks pass. Still creates audit trail.
    pub async fn propose_auto(
        &self,
        action: ActionType,
        reason: String,
        source: String,
        confidence: Option<f64>,
        auto_approve: bool,
    ) -> Result<String, String> {
        self.propose_internal(action, reason, source, confidence, auto_approve)
            .await
    }

    async fn propose_internal(
        &self,
        action: ActionType,
        reason: String,
        source: String,
        confidence: Option<f64>,
        auto_approve: bool,
    ) -> Result<String, String> {
        // Safety and identity capture ALWAYS run, even for auto-approved actions.
        let target_identity = match &action {
            ActionType::KillProcess { pid, .. } => {
                safety::SafetyGuard::is_safe_to_kill(*pid)?;
                Some(
                    self.identity_provider
                        .identity_for_pid(*pid)
                        .map_err(|err| err.to_string())?,
                )
            }
        };

        let id = format!("action-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        let now = current_epoch_secs();

        let (status, approved_by, approved_at) = if auto_approve {
            (
                ActionStatus::Approved,
                Some("circuit_breaker".to_string()),
                Some(now),
            )
        } else {
            (ActionStatus::Pending, None, None)
        };

        let enforcement_action = EnforcementAction {
            id: id.clone(),
            action,
            target_identity,
            reason: reason.clone(),
            source: source.clone(),
            confidence,
            status,
            created_at: now,
            expires_at: now + self.ttl_secs,
            executed_at_ms: None,
            approved_by: approved_by.clone(),
            approved_at,
        };

        self.actions
            .write()
            .await
            .insert(id.clone(), enforcement_action);

        if auto_approve {
            log::warn!(
                target: "linnix_audit",
                "CIRCUIT_BREAKER auto-approved {} source={} reason={}",
                id, source, reason
            );
        } else {
            log::info!("[enforcement] proposed {id}");
        }

        Ok(id)
    }

    pub async fn execute_approved(&self, id: &str) -> Result<(), String> {
        self.execute_approved_at(id, current_epoch_secs()).await
    }

    async fn execute_approved_at(&self, id: &str, now: u64) -> Result<(), String> {
        let action = self.get_by_id(id).await.ok_or("action not found")?;

        if action.status != ActionStatus::Approved {
            return Err(format!("not approved: {:?}", action.status));
        }

        match action.action {
            ActionType::KillProcess { pid, signal } => {
                self.execute_approved_kill(&action, pid, signal, now).await
            }
        }
    }

    async fn execute_approved_kill(
        &self,
        action: &EnforcementAction,
        pid: u32,
        signal: i32,
        now: u64,
    ) -> Result<(), String> {
        let expected = match action.target_identity.as_ref() {
            Some(identity) => identity,
            None => {
                return self
                    .fail_execution(
                        &action.id,
                        "kill action has no captured process identity".to_string(),
                    )
                    .await;
            }
        };

        if now > action.expires_at {
            return self
                .fail_execution(
                    &action.id,
                    ProcessIdentityError::Expired {
                        pid,
                        expires_at: action.expires_at,
                        now,
                    }
                    .to_string(),
                )
                .await;
        }

        let signal_handle = match self.signal_sender.open_handle(pid) {
            Ok(handle) => handle,
            Err(err) => {
                return self
                    .fail_execution(&action.id, format!("pidfd open failed: {err}"))
                    .await;
            }
        };

        if let Err(err) = safety::SafetyGuard::is_safe_to_kill(pid) {
            return self
                .fail_execution(&action.id, format!("unsafe immediately before kill: {err}"))
                .await;
        }

        let current = match self.identity_provider.identity_for_pid(pid) {
            Ok(identity) => identity,
            Err(err) => return self.fail_execution(&action.id, err.to_string()).await,
        };

        if !expected.same_process_as(&current) {
            return self
                .fail_execution(
                    &action.id,
                    ProcessIdentityError::Mismatch {
                        pid,
                        expected: Box::new(expected.clone()),
                        actual: Box::new(current),
                    }
                    .to_string(),
                )
                .await;
        }

        log::info!("[enforcement] EXECUTING KILL pid={pid} signal={signal}");
        match signal_handle.send_signal(signal) {
            Ok(()) => self.complete(&action.id).await,
            Err(err) => {
                // The process was already gone, or the signal was refused.
                // Marking this executed would let a later fall in pressure be
                // credited to a kill that never landed.
                self.fail_execution(&action.id, format!("kill failed: {err}"))
                    .await
            }
        }
    }

    async fn fail_execution(&self, id: &str, why: String) -> Result<(), String> {
        let _ = self.fail(id, why.clone()).await;
        Err(why)
    }

    pub async fn approve(&self, id: &str, approver: String) -> Result<EnforcementAction, String> {
        let mut actions = self.actions.write().await;
        let action = actions.get_mut(id).ok_or("action not found")?;

        if action.status != ActionStatus::Pending {
            return Err(format!("not pending: {:?}", action.status));
        }

        let now = current_epoch_secs();
        if now > action.expires_at {
            action.status = ActionStatus::Expired;
            return Err("expired".to_string());
        }

        action.status = ActionStatus::Approved;
        action.approved_by = Some(approver.clone());
        action.approved_at = Some(now);

        log::warn!(
            target: "linnix_audit",
            "APPROVED {} by {} reason={}",
            id, approver, action.reason
        );

        Ok(action.clone())
    }

    pub async fn reject(&self, id: &str, rejector: String) -> Result<(), String> {
        let mut actions = self.actions.write().await;
        let action = actions.get_mut(id).ok_or("action not found")?;

        if action.status != ActionStatus::Pending {
            return Err(format!("not pending: {:?}", action.status));
        }

        action.status = ActionStatus::Rejected;
        log::info!("[enforcement] rejected {id} by {rejector}");
        Ok(())
    }

    pub async fn complete(&self, id: &str) -> Result<(), String> {
        let mut actions = self.actions.write().await;
        let action = actions.get_mut(id).ok_or("action not found")?;

        if action.status != ActionStatus::Approved {
            return Err(format!("not approved: {:?}", action.status));
        }

        action.status = ActionStatus::Executed;
        action.executed_at_ms = Some(current_epoch_millis());
        // Every execution bumps this. A recovery watch samples system-wide
        // pressure, so a *later* kill landing mid-watch invalidates the
        // measurement in progress — the earlier action would otherwise be
        // credited with a fall the second kill caused.
        self.executions.fetch_add(1, Ordering::SeqCst);
        log::info!("[enforcement] completed {id}");
        Ok(())
    }

    #[allow(dead_code)]
    /// Marks an action the executor could not carry out.
    ///
    /// Valid from `Approved`, which is the state an action is in while the
    /// executor is working on it — `reject` is the operator's path and only
    /// applies to pending proposals.
    pub async fn fail(&self, id: &str, why: String) -> Result<(), String> {
        let mut actions = self.actions.write().await;
        let action = actions.get_mut(id).ok_or("action not found")?;

        if action.status != ActionStatus::Approved {
            return Err(format!("not approved: {:?}", action.status));
        }

        action.status = ActionStatus::Failed;
        log::warn!("[enforcement] {id} failed: {why}");
        Ok(())
    }

    /// How many actions have executed so far. A change during a recovery
    /// watch means another intervention overlapped it.
    pub fn execution_count(&self) -> u64 {
        self.executions.load(Ordering::SeqCst)
    }

    pub async fn get_pending(&self) -> Vec<EnforcementAction> {
        let now = current_epoch_secs();
        let mut actions = self.actions.write().await;

        for action in actions.values_mut() {
            if action.status == ActionStatus::Pending && now > action.expires_at {
                action.status = ActionStatus::Expired;
            }
        }

        actions
            .values()
            .filter(|a| a.status == ActionStatus::Pending)
            .cloned()
            .collect()
    }

    pub async fn get_by_id(&self, id: &str) -> Option<EnforcementAction> {
        self.actions.read().await.get(id).cloned()
    }

    pub async fn get_all(&self) -> Vec<EnforcementAction> {
        self.actions.read().await.values().cloned().collect()
    }
}

fn current_epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct ScriptedIdentityProvider {
        responses: Mutex<VecDeque<Result<ProcessIdentity, ProcessIdentityError>>>,
    }

    impl ScriptedIdentityProvider {
        fn new(responses: Vec<Result<ProcessIdentity, ProcessIdentityError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
            }
        }
    }

    impl ProcessIdentityProvider for ScriptedIdentityProvider {
        fn identity_for_pid(&self, pid: u32) -> Result<ProcessIdentity, ProcessIdentityError> {
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| panic!("no scripted identity response for pid {pid}"))
        }
    }

    #[derive(Debug, Default)]
    struct RecordingSignalSender {
        opened: Mutex<Vec<u32>>,
        sent: Arc<Mutex<Vec<(u32, i32)>>>,
    }

    impl RecordingSignalSender {
        fn opened(&self) -> Vec<u32> {
            self.opened.lock().unwrap().clone()
        }

        fn sent(&self) -> Vec<(u32, i32)> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl SignalSender for RecordingSignalSender {
        fn open_handle(&self, pid: u32) -> Result<Box<dyn SignalHandle>, std::io::Error> {
            self.opened.lock().unwrap().push(pid);
            Ok(Box::new(RecordingSignalHandle {
                pid,
                sent: Arc::clone(&self.sent),
            }))
        }
    }

    #[derive(Debug)]
    struct RecordingSignalHandle {
        pid: u32,
        sent: Arc<Mutex<Vec<(u32, i32)>>>,
    }

    impl SignalHandle for RecordingSignalHandle {
        fn send_signal(&self, signal: i32) -> Result<(), std::io::Error> {
            self.sent.lock().unwrap().push((self.pid, signal));
            Ok(())
        }
    }

    fn queue_with_components(
        ttl_secs: u64,
        responses: Vec<Result<ProcessIdentity, ProcessIdentityError>>,
    ) -> (EnforcementQueue, Arc<RecordingSignalSender>) {
        let signal_sender = Arc::new(RecordingSignalSender::default());
        (
            EnforcementQueue::new_for_test_with_components(
                ttl_secs,
                Arc::new(ScriptedIdentityProvider::new(responses)),
                signal_sender.clone(),
            ),
            signal_sender,
        )
    }

    async fn propose_auto_kill(queue: &EnforcementQueue, pid: u32) -> String {
        queue
            .propose_auto(
                ActionType::KillProcess { pid, signal: 9 },
                "test".to_string(),
                "circuit_breaker".to_string(),
                None,
                true,
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn kill_action_requires_approval_by_operator() {
        // Given: An SRE proposes killing a noisy process
        let queue = EnforcementQueue::new_for_test(300);
        let action_id = queue
            .propose(
                ActionType::KillProcess {
                    pid: 123,
                    signal: 9,
                },
                "consuming 90% CPU".to_string(),
                "circuit_breaker".to_string(),
                None,
            )
            .await
            .unwrap();

        // When: The operator approves the action
        let result = queue.approve(&action_id, "alice".to_string()).await;

        // Then: The action is marked as approved and ready for execution
        assert!(result.is_ok());
        let action = queue.get_by_id(&action_id).await.unwrap();
        assert_eq!(action.status, ActionStatus::Approved);
        assert_eq!(action.approved_by, Some("alice".to_string()));
    }

    #[tokio::test]
    async fn expired_actions_cannot_be_approved() {
        // Given: A kill action with a 0-second TTL (expires immediately)
        let queue = EnforcementQueue::new_for_test(0);
        let action_id = queue
            .propose(
                ActionType::KillProcess {
                    pid: 123,
                    signal: 9,
                },
                "high CPU usage".to_string(),
                "circuit_breaker".to_string(),
                None,
            )
            .await
            .unwrap();

        // When: An operator tries to approve after waiting 1 second
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let result = queue.approve(&action_id, "alice".to_string()).await;

        // Then: Approval fails with an expiration error
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[tokio::test]
    async fn rejected_actions_cannot_be_approved_later() {
        // Given: A proposed kill action
        let queue = EnforcementQueue::new_for_test(300);
        let action_id = queue
            .propose(
                ActionType::KillProcess {
                    pid: 123,
                    signal: 9,
                },
                "suspected false positive".to_string(),
                "circuit_breaker".to_string(),
                None,
            )
            .await
            .unwrap();

        // When: An operator rejects it
        queue.reject(&action_id, "bob".to_string()).await.unwrap();

        // Then: The action is marked rejected
        let action = queue.get_by_id(&action_id).await.unwrap();
        assert_eq!(action.status, ActionStatus::Rejected);

        // And: Another operator cannot approve it
        let result = queue.approve(&action_id, "alice".to_string()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn approved_actions_cannot_be_rejected() {
        // Given: A kill action approved by an operator
        let queue = EnforcementQueue::new_for_test(300);
        let action_id = queue
            .propose(
                ActionType::KillProcess {
                    pid: 123,
                    signal: 9,
                },
                "high memory usage".to_string(),
                "circuit_breaker".to_string(),
                None,
            )
            .await
            .unwrap();
        queue
            .approve(&action_id, "alice".to_string())
            .await
            .unwrap();

        // When: Another operator tries to reject it
        let result = queue.reject(&action_id, "bob".to_string()).await;

        // Then: Rejection fails because the action is no longer pending
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not pending"));
    }

    #[tokio::test]
    async fn pid_reuse_fails_before_signal_is_sent() {
        let pid = 123;
        let original = ProcessIdentity::for_test(pid);
        let mut reused = original.clone();
        reused.start_time_ticks += 1;
        reused.stat_comm = "reused-process".to_string();
        let (queue, signal_sender) = queue_with_components(60, vec![Ok(original), Ok(reused)]);
        let action_id = propose_auto_kill(&queue, pid).await;

        let err = queue.execute_approved(&action_id).await.unwrap_err();

        assert!(err.contains("identity changed"));
        assert_eq!(signal_sender.opened(), vec![pid]);
        assert_eq!(signal_sender.sent(), Vec::<(u32, i32)>::new());
        let action = queue.get_by_id(&action_id).await.unwrap();
        assert_eq!(action.status, ActionStatus::Failed);
    }

    #[tokio::test]
    async fn expired_identity_fails_before_signal_is_sent() {
        let pid = 123;
        let original = ProcessIdentity::for_test(pid);
        let (queue, signal_sender) = queue_with_components(60, vec![Ok(original)]);
        let action_id = propose_auto_kill(&queue, pid).await;
        let expires_at = queue.get_by_id(&action_id).await.unwrap().expires_at;

        let err = queue
            .execute_approved_at(&action_id, expires_at + 1)
            .await
            .unwrap_err();

        assert!(err.contains("expired"));
        assert_eq!(signal_sender.opened(), Vec::<u32>::new());
        assert_eq!(signal_sender.sent(), Vec::<(u32, i32)>::new());
        let action = queue.get_by_id(&action_id).await.unwrap();
        assert_eq!(action.status, ActionStatus::Failed);
    }

    #[tokio::test]
    async fn missing_process_before_kill_fails_before_signal_is_sent() {
        let pid = 123;
        let original = ProcessIdentity::for_test(pid);
        let (queue, signal_sender) = queue_with_components(
            60,
            vec![Ok(original), Err(ProcessIdentityError::Missing { pid })],
        );
        let action_id = propose_auto_kill(&queue, pid).await;

        let err = queue.execute_approved(&action_id).await.unwrap_err();

        assert!(err.contains("missing"));
        assert_eq!(signal_sender.opened(), vec![pid]);
        assert_eq!(signal_sender.sent(), Vec::<(u32, i32)>::new());
        let action = queue.get_by_id(&action_id).await.unwrap();
        assert_eq!(action.status, ActionStatus::Failed);
    }

    #[tokio::test]
    async fn matching_identity_is_signaled_once_and_completed() {
        let pid = 123;
        let original = ProcessIdentity::for_test(pid);
        let (queue, signal_sender) =
            queue_with_components(60, vec![Ok(original.clone()), Ok(original)]);
        let action_id = propose_auto_kill(&queue, pid).await;

        queue.execute_approved(&action_id).await.unwrap();

        assert_eq!(signal_sender.opened(), vec![pid]);
        assert_eq!(signal_sender.sent(), vec![(pid, 9)]);
        let action = queue.get_by_id(&action_id).await.unwrap();
        assert_eq!(action.status, ActionStatus::Executed);
        assert!(action.executed_at_ms.is_some());
    }
}
