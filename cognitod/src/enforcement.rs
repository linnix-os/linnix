use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

mod safety;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ActionType {
    KillProcess { pid: u32, signal: i32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ActionStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnforcementAction {
    pub id: String,
    pub action: ActionType,
    pub reason: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    pub status: ActionStatus,
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<u64>,
}

pub struct EnforcementQueue {
    next_id: AtomicU64,
    actions: RwLock<HashMap<String, EnforcementAction>>,
    ttl_secs: u64,
}

impl EnforcementQueue {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            actions: RwLock::new(HashMap::new()),
            ttl_secs,
        }
    }

    pub async fn propose(
        &self,
        action: ActionType,
        reason: String,
        source: String,
        confidence: Option<f64>,
    ) -> Result<String, String> {
        match &action {
            ActionType::KillProcess { pid, .. } => {
                safety::SafetyGuard::is_safe_to_kill(*pid)?;
            }
        }

        let id = format!("action-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        let now = current_epoch_secs();

        let enforcement_action = EnforcementAction {
            id: id.clone(),
            action,
            reason,
            source,
            confidence,
            status: ActionStatus::Pending,
            created_at: now,
            expires_at: now + self.ttl_secs,
            approved_by: None,
            approved_at: None,
        };

        self.actions
            .write()
            .await
            .insert(id.clone(), enforcement_action);
        log::info!("[enforcement] proposed {id}");
        Ok(id)
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

    #[allow(dead_code)]
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

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_propose_and_approve() {
        let queue = EnforcementQueue::new(300);
        let id = queue
            .propose(
                ActionType::KillProcess {
                    pid: 123,
                    signal: 9,
                },
                "test".to_string(),
                "test".to_string(),
                None,
            )
            .await.unwrap();

        let pending = queue.get_pending().await;
        assert_eq!(pending.len(), 1);

        let result = queue.approve(&id, "alice".to_string()).await;
        assert!(result.is_ok());

        let action = queue.get_by_id(&id).await.unwrap();
        assert_eq!(action.status, ActionStatus::Approved);
        assert_eq!(action.approved_by, Some("alice".to_string()));
    }

    #[tokio::test]
    async fn test_expiration() {
        let queue = EnforcementQueue::new(0); // Expire immediately (0 seconds TTL)
        let id = queue
            .propose(
                ActionType::KillProcess {
                    pid: 123,
                    signal: 9,
                },
                "test".to_string(),
                "test".to_string(),
                None,
            )
            .await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let result = queue.approve(&id, "alice".to_string()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[tokio::test]
    async fn test_reject() {
        let queue = EnforcementQueue::new(300);
        let id = queue
            .propose(
                ActionType::KillProcess {
                    pid: 123,
                    signal: 9,
                },
                "test".to_string(),
                "test".to_string(),
                None,
            )
            .await.unwrap();

        queue.reject(&id, "bob".to_string()).await.unwrap();

        let action = queue.get_by_id(&id).await.unwrap();
        assert_eq!(action.status, ActionStatus::Rejected);

        let result = queue.approve(&id, "alice".to_string()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reject_already_approved() {
        let queue = EnforcementQueue::new(300);
        let id = queue
            .propose(
                ActionType::KillProcess {
                    pid: 123,
                    signal: 9,
                },
                "test".to_string(),
                "test".to_string(),
                None,
            )
            .await.unwrap();

        queue.approve(&id, "alice".to_string()).await.unwrap();

        let result = queue.reject(&id, "bob".to_string()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not pending"));
    }
}
