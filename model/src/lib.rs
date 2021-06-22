use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct BindRequest {
    pub name: String,
    pub password: String,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub enum RequestFilter {
    And(Vec<RequestFilter>),
    Or(Vec<RequestFilter>),
    Not(Box<RequestFilter>),
    Equality(String, String),
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct ListUsersRequest {
    pub filters: Option<RequestFilter>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(sqlx::FromRow))]
pub struct User {
    pub user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    // pub avatar: ?,
    pub ssh_pub_key: Option<String>,
    pub wireguard_pub_key: Option<String>,
    pub creation_date: chrono::NaiveDateTime,
}

impl Default for User {
    fn default() -> Self {
        User {
            user_id: String::new(),
            email: String::new(),
            display_name: None,
            first_name: None,
            last_name: None,
            ssh_pub_key: None,
            wireguard_pub_key: None,
            creation_date: chrono::NaiveDateTime::from_timestamp(0, 0),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Default)]
pub struct CreateUserRequest {
    // Same fields as User, but no creation_date, and with password.
    pub user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub ssh_pub_key: Option<String>,
    pub wireguard_pub_key: Option<String>,
    pub password: String,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Default)]
pub struct DeleteUserRequest {
    pub user_id: String,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Group {
    pub display_name: String,
    pub users: Vec<String>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub display_name: String,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AddUserToGroupRequest {
    pub user_id: String,
    pub group_id: i32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct JWTClaims {
    pub exp: DateTime<Utc>,
    pub iat: DateTime<Utc>,
    pub user: String,
    pub groups: HashSet<String>,
}
