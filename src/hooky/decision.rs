use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Allow,
    Block,
    Rewrite,
    Confirm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    pub kind: DecisionKind,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rewritten_command: Option<String>,
    pub engine: String,
}

impl Decision {
    pub fn allow(reason: impl Into<String>, engine: impl Into<String>) -> Self {
        Self {
            kind: DecisionKind::Allow,
            reason: reason.into(),
            rule_id: None,
            rewritten_command: None,
            engine: engine.into(),
        }
    }

    pub fn block(
        reason: impl Into<String>,
        engine: impl Into<String>,
        rule_id: Option<String>,
    ) -> Self {
        Self {
            kind: DecisionKind::Block,
            reason: reason.into(),
            rule_id,
            rewritten_command: None,
            engine: engine.into(),
        }
    }

    pub fn rewrite(
        reason: impl Into<String>,
        engine: impl Into<String>,
        rule_id: Option<String>,
        rewritten_command: impl Into<String>,
    ) -> Self {
        Self {
            kind: DecisionKind::Rewrite,
            reason: reason.into(),
            rule_id,
            rewritten_command: Some(rewritten_command.into()),
            engine: engine.into(),
        }
    }
}
