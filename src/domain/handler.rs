use super::sql_tables::*;
use crate::infra::configuration::Configuration;
use anyhow::{bail, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use sea_query::{Expr, MysqlQueryBuilder, Query, SimpleExpr};
use sqlx::any::AnyPool;
use sqlx::Row;

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct BindRequest {
    pub name: String,
    pub password: String,
}

#[derive(PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum RequestFilter {
    And(Vec<RequestFilter>),
    Or(Vec<RequestFilter>),
    Not(Box<RequestFilter>),
    Equality(String, String),
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct ListUsersRequest {
    pub filters: Option<RequestFilter>,
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct User {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    // pub avatar: ?,
    pub creation_date: chrono::NaiveDateTime,
}

#[async_trait]
pub trait BackendHandler: Clone + Send {
    async fn bind(&mut self, request: BindRequest) -> Result<()>;
    async fn list_users(&mut self, request: ListUsersRequest) -> Result<Vec<User>>;
}

#[derive(Debug, Clone)]
pub struct SqlBackendHandler {
    config: Configuration,
    sql_pool: AnyPool,
    authenticated: bool,
}

impl SqlBackendHandler {
    pub fn new(config: Configuration, sql_pool: AnyPool) -> Self {
        SqlBackendHandler {
            config,
            sql_pool,
            authenticated: false,
        }
    }
}

fn passwords_match(encrypted_password: &str, clear_password: &str) -> bool {
    encrypted_password == clear_password
}

fn get_filter_expr(filter: RequestFilter) -> SimpleExpr {
    use RequestFilter::*;
    fn get_repeated_filter(
        fs: Vec<RequestFilter>,
        field: &dyn Fn(SimpleExpr, SimpleExpr) -> SimpleExpr,
    ) -> SimpleExpr {
        let mut it = fs.into_iter();
        let first_expr = match it.next() {
            None => return Expr::value(true),
            Some(f) => get_filter_expr(f),
        };
        it.fold(first_expr, |e, f| field(e, get_filter_expr(f)))
    }
    match filter {
        And(fs) => get_repeated_filter(fs, &SimpleExpr::and),
        Or(fs) => get_repeated_filter(fs, &SimpleExpr::or),
        Not(f) => Expr::not(Expr::expr(get_filter_expr(*f))),
        Equality(s1, s2) => Expr::expr(Expr::cust(&s1)).eq(s2),
    }
}

#[async_trait]
impl BackendHandler for SqlBackendHandler {
    async fn bind(&mut self, request: BindRequest) -> Result<()> {
        if request.name == self.config.ldap_user_dn {
            if request.password == self.config.ldap_user_pass {
                self.authenticated = true;
                return Ok(());
            } else {
                bail!(r#"Authentication error for "{}""#, request.name)
            }
        }
        let query = Query::select()
            .column(Users::Password)
            .from(Users::Table)
            .and_where(Expr::col(Users::UserId).eq(request.name.as_str()))
            .to_string(MysqlQueryBuilder);
        if let Ok(row) = sqlx::query(&query).fetch_one(&self.sql_pool).await {
            if passwords_match(&request.password, &row.get::<String, _>("password")) {
                return Ok(());
            }
        }
        bail!(r#"Authentication error for "{}""#, request.name)
    }

    async fn list_users(&mut self, request: ListUsersRequest) -> Result<Vec<User>> {
        let query = {
            let mut query_builder = Query::select()
                .column(Users::UserId)
                .column(Users::Email)
                .column(Users::DisplayName)
                .column(Users::FirstName)
                .column(Users::LastName)
                .column(Users::Avatar)
                .column(Users::CreationDate)
                .from(Users::Table)
                .to_owned();
            if let Some(filter) = request.filters {
                if filter != RequestFilter::And(Vec::new())
                    && filter != RequestFilter::Or(Vec::new())
                {
                    query_builder.and_where(get_filter_expr(filter));
                }
            }

            query_builder.to_string(MysqlQueryBuilder)
        };

        let results = sqlx::query(&query)
            .map(|row: sqlx::any::AnyRow| User {
                user_id: row.get::<String, _>("user_id"),
                email: row.get::<String, _>("email"),
                display_name: row.get::<String, _>("display_name"),
                first_name: row.get::<String, _>("first_name"),
                last_name: row.get::<String, _>("last_name"),
                creation_date: chrono::NaiveDateTime::from_timestamp(0, 0), // TODO: wait until datetime is supported for Any.
            })
            .fetch(&self.sql_pool)
            .collect::<Vec<sqlx::Result<User>>>()
            .await;

        Ok(results.into_iter().collect::<sqlx::Result<Vec<User>>>()?)
    }
}

#[cfg(test)]
mockall::mock! {
    pub TestBackendHandler{}
    impl Clone for TestBackendHandler {
        fn clone(&self) -> Self;
    }
    #[async_trait]
    impl BackendHandler for TestBackendHandler {
        async fn bind(&mut self, request: BindRequest) -> Result<()>;
        async fn list_users(&mut self, request: ListUsersRequest) -> Result<Vec<User>>;
    }
}