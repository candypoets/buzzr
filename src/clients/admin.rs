//! Trusted local relay administration through its Compose services.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use super::{err, run_with_timeout, CommandError};

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Administer a local Buzz relay via `docker compose exec`.
#[derive(Debug, Clone)]
pub struct LocalBuzzAdmin {
    pub compose_file: PathBuf,
    pub relay_service: String,
    pub postgres_service: String,
    pub postgres_user: String,
    pub postgres_database: String,
    pub docker_binary: String,
}

impl LocalBuzzAdmin {
    pub fn new(compose_file: PathBuf) -> Self {
        LocalBuzzAdmin {
            compose_file,
            relay_service: "relay".to_string(),
            postgres_service: "postgres".to_string(),
            postgres_user: "buzz".to_string(),
            postgres_database: "buzz".to_string(),
            docker_binary: "docker".to_string(),
        }
    }

    fn compose(
        &self,
        service: &str,
        args: &[String],
        timeout: u64,
    ) -> Result<String, CommandError> {
        let mut command = Command::new(&self.docker_binary);
        command
            .arg("compose")
            .arg("-f")
            .arg(&self.compose_file)
            .arg("exec")
            .arg("-T")
            .arg(service)
            .args(args);
        if let Some(parent) = self
            .compose_file
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            command.current_dir(parent);
        }
        let output = run_with_timeout(&mut command, None, Duration::from_secs(timeout)).map_err(
            |error| CommandError(format!("failed to run local Buzz admin command: {error}")),
        )?;
        if output.code != 0 {
            return err(format!(
                "local Buzz admin command failed: {}",
                output.failure_message()
            ));
        }
        Ok(output.stdout.trim().to_string())
    }

    /// Add a pubkey to the local relay membership list.
    pub fn add_relay_member(&self, pubkey: &str) -> Result<(), CommandError> {
        if !is_hex64(pubkey) {
            return err("invalid pubkey for relay membership");
        }
        self.compose(
            &self.relay_service,
            &[
                "buzz-admin".to_string(),
                "add-member".to_string(),
                "--pubkey".to_string(),
                pubkey.to_string(),
                "--role".to_string(),
                "member".to_string(),
            ],
            45,
        )?;
        Ok(())
    }

    /// All member pubkeys currently known to the local relay.
    pub fn relay_member_pubkeys(&self) -> Result<HashSet<String>, CommandError> {
        let output = self.compose(
            &self.relay_service,
            &["buzz-admin".to_string(), "list-members".to_string()],
            45,
        )?;
        Ok(output
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .map(str::to_lowercase)
            .filter(|candidate| is_hex64(candidate))
            .collect())
    }

    /// Remove a relay membership if it still exists. Returning `false` for an
    /// already-absent member makes interrupted deprovisioning safe to retry.
    pub fn remove_relay_member(&self, pubkey: &str) -> Result<bool, CommandError> {
        if !is_hex64(pubkey) {
            return err("invalid pubkey for relay membership");
        }
        if !self.relay_member_pubkeys()?.contains(pubkey) {
            return Ok(false);
        }
        self.compose(
            &self.relay_service,
            &[
                "buzz-admin".to_string(),
                "remove-member".to_string(),
                "--pubkey".to_string(),
                pubkey.to_string(),
            ],
            45,
        )?;
        Ok(true)
    }

    fn psql(&self, sql: &str) -> Result<Vec<String>, CommandError> {
        let output = self.compose(
            &self.postgres_service,
            &[
                "psql".to_string(),
                "-v".to_string(),
                "ON_ERROR_STOP=1".to_string(),
                "-U".to_string(),
                self.postgres_user.clone(),
                "-d".to_string(),
                self.postgres_database.clone(),
                "-Atc".to_string(),
                sql.to_string(),
            ],
            45,
        )?;
        Ok(output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// Resolve the single local community a human pubkey belongs to.
    pub fn community_for_human(&self, human_pubkey: &str) -> Result<String, CommandError> {
        if !is_hex64(human_pubkey) {
            return err("invalid human pubkey");
        }
        let rows = self.psql(&format!(
            "SELECT DISTINCT community_id::text FROM (\
             SELECT community_id FROM users WHERE pubkey = decode('{human_pubkey}','hex') \
             AND deactivated_at IS NULL UNION ALL \
             SELECT community_id FROM relay_members WHERE lower(pubkey) = '{human_pubkey}'\
             ) q ORDER BY 1;"
        ))?;
        if rows.len() != 1 {
            return err(format!(
                "human pubkey must resolve to exactly one local Buzz community \
                 (found {})",
                rows.len()
            ));
        }
        uuid::Uuid::parse_str(&rows[0])
            .map_err(|_| CommandError("local Buzz returned an invalid community id".to_string()))?;
        Ok(rows[0].clone())
    }

    /// Idempotently bind plugin-controlled identities to the human pubkey.
    pub fn assign_agent_owner(
        &self,
        human_pubkey: &str,
        agent_pubkeys: &[String],
    ) -> Result<(), CommandError> {
        let community_id = self.community_for_human(human_pubkey)?;
        let unique: std::collections::BTreeSet<&String> = agent_pubkeys.iter().collect();
        for agent_pubkey in unique {
            if agent_pubkey == human_pubkey {
                continue;
            }
            if !is_hex64(agent_pubkey) {
                return err("invalid agent pubkey");
            }
            // A kind:0 profile normally creates this row first. The insert makes
            // bootstrap deterministic if the relay's side-effect worker lags.
            let rows = self.psql(&format!(
                "INSERT INTO users (community_id, pubkey) VALUES ('{community_id}'::uuid, \
                 decode('{agent_pubkey}','hex')) ON CONFLICT (community_id, pubkey) DO NOTHING; \
                 UPDATE users SET agent_owner_pubkey = decode('{human_pubkey}','hex'), \
                 updated_at = NOW() WHERE community_id = '{community_id}'::uuid \
                 AND pubkey = decode('{agent_pubkey}','hex') \
                 AND (agent_owner_pubkey IS NULL \
                 OR agent_owner_pubkey = decode('{human_pubkey}','hex')); \
                 SELECT COALESCE(encode(agent_owner_pubkey,'hex'),'') FROM users \
                 WHERE community_id = '{community_id}'::uuid \
                 AND pubkey = decode('{agent_pubkey}','hex');"
            ))?;
            if rows.last().map(String::as_str) != Some(human_pubkey) {
                return err(format!(
                    "agent {} is already owned by another pubkey",
                    &agent_pubkey[..12]
                ));
            }
        }
        Ok(())
    }

    /// Clear an ownership link only while it still points at the expected
    /// human. A missing row or a changed owner is preserved and returns false.
    pub fn clear_agent_owner(
        &self,
        human_pubkey: &str,
        agent_pubkey: &str,
    ) -> Result<bool, CommandError> {
        if !is_hex64(human_pubkey) {
            return err("invalid human pubkey");
        }
        if !is_hex64(agent_pubkey) {
            return err("invalid agent pubkey");
        }
        let community_id = self.community_for_human(human_pubkey)?;
        let rows = self.psql(&format!(
            "UPDATE users SET agent_owner_pubkey = NULL, updated_at = NOW() \
             WHERE community_id = '{community_id}'::uuid \
             AND pubkey = decode('{agent_pubkey}','hex') \
             AND agent_owner_pubkey = decode('{human_pubkey}','hex') \
             RETURNING 'cleared';"
        ))?;
        Ok(rows.last().map(String::as_str) == Some("cleared"))
    }
}
