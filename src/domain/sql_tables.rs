use sea_query::*;

pub type Pool = sqlx::sqlite::SqlitePool;
pub type PoolOptions = sqlx::sqlite::SqlitePoolOptions;
pub type DbRow = sqlx::sqlite::SqliteRow;
pub type DbQueryBuilder = SqliteQueryBuilder;

#[derive(Iden)]
pub enum Users {
    Table,
    UserId,
    Email,
    DisplayName,
    FirstName,
    LastName,
    Avatar,
    SshPubKey,
    WireguardPubKey,
    CreationDate,
    PasswordHash,
    TotpSecret,
    MfaType,
}

#[derive(Iden)]
pub enum Groups {
    Table,
    GroupId,
    DisplayName,
}

#[derive(Iden)]
pub enum Memberships {
    Table,
    UserId,
    GroupId,
}

pub async fn init_table(pool: &Pool) -> sqlx::Result<()> {
    // SQLite needs this pragma to be turned on. Other DB might not understand this, so ignore the
    // error.
    let _ = sqlx::query("PRAGMA foreign_keys = ON").execute(pool).await;
    sqlx::query(
        &Table::create()
            .table(Users::Table)
            .if_not_exists()
            .col(
                ColumnDef::new(Users::UserId)
                    .string_len(255)
                    .not_null()
                    .primary_key(),
            )
            .col(ColumnDef::new(Users::Email).string_len(255).not_null())
            .col(ColumnDef::new(Users::DisplayName).string_len(255))
            .col(ColumnDef::new(Users::FirstName).string_len(255))
            .col(ColumnDef::new(Users::LastName).string_len(255))
            .col(ColumnDef::new(Users::SshPubKey).string_len(768))
            .col(ColumnDef::new(Users::WireguardPubKey).string_len(255))
            .col(ColumnDef::new(Users::Avatar).binary())
            .col(ColumnDef::new(Users::CreationDate).date_time().not_null())
            .col(
                ColumnDef::new(Users::PasswordHash)
                    .string_len(255)
                    .not_null(),
            )
            .col(ColumnDef::new(Users::TotpSecret).string_len(64))
            .col(ColumnDef::new(Users::MfaType).string_len(64))
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await?;
    sqlx::query(
        &Table::create()
            .table(Groups::Table)
            .if_not_exists()
            .col(
                ColumnDef::new(Groups::GroupId)
                    .integer()
                    .not_null()
                    .primary_key(),
            )
            .col(
                ColumnDef::new(Groups::DisplayName)
                    .string_len(255)
                    .unique_key()
                    .not_null(),
            )
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await?;
    sqlx::query(
        &Table::create()
            .table(Memberships::Table)
            .if_not_exists()
            .col(
                ColumnDef::new(Memberships::UserId)
                    .string_len(255)
                    .not_null(),
            )
            .col(ColumnDef::new(Memberships::GroupId).integer().not_null())
            .foreign_key(
                ForeignKey::create()
                    .name("MembershipUserForeignKey")
                    .table(Memberships::Table, Users::Table)
                    .col(Memberships::UserId, Users::UserId)
                    .on_delete(ForeignKeyAction::Cascade)
                    .on_update(ForeignKeyAction::Cascade),
            )
            .foreign_key(
                ForeignKey::create()
                    .name("MembershipGroupForeignKey")
                    .table(Memberships::Table, Groups::Table)
                    .col(Memberships::GroupId, Groups::GroupId)
                    .on_delete(ForeignKeyAction::Cascade)
                    .on_update(ForeignKeyAction::Cascade),
            )
            .to_string(DbQueryBuilder {}),
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDateTime;
    use sqlx::{Column, Row};

    #[actix_rt::test]
    async fn test_init_table() {
        let sql_pool = PoolOptions::new().connect("sqlite::memory:").await.unwrap();
        init_table(&sql_pool).await.unwrap();
        sqlx::query(r#"INSERT INTO users
      (user_id, email, display_name, first_name, last_name, ssh_pub_key, wireguard_pub_key, creation_date, password_hash)
      VALUES ("bôb", "böb@bob.bob", "Bob Bobbersön", "Bob", "Bobberson", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCpGRD9/jaGg/aM4jbbumjqnIUT+wtyaeb2Z27AZUlsAo+4GdDGkxC0LnLSuLqQleoMWcVG6RvJrTsa5NWQwNJmnX4rS7bJ+6qZibXHhfyA5Kr6JybWZr4/mrPPKgBaio6kPEqKkfEzhrygpeXcNvxp847gu+Hn7IbI6eBr0sLfy/bJPkpzhyhSSt/kA5drLJvxdA9aNPv3Jr0kJQtlceH4f7334LH9EE18xy8dEX/w0iefFSEC8rXoV7svqINOQKULIhi14ibAX9a4ks9TjKXqEDrJWQe0gf6qNEQ2wS8j5d47mdKnxPG0d592FHO86LlGiIpWkJt2WmoNmJHnwR1LrUsJK6T3tgjZyL+plcnS9OlBDD74dA1DQSpXaGkcLADNui9+cA/T1nacrzR9V8BN6HIBmvtqaI0CKz9lbScJVkNpkmxKraj/TgcWNpSWKDOuo8kdQKOeGcsxcK9PtpoCB/+dHe5gCf7/QHY1BIoyrsM/sOi0f2+f9zHDg1OIh6U= test@example", "e1ofBntxh2mj8kvdfODOL19xJyqVczDybDQuJ3sW30o=", "1970-01-01 00:00:00", "bob00")"#).execute(&sql_pool).await.unwrap();
        let row =
            sqlx::query(r#"SELECT display_name, creation_date FROM users WHERE user_id = "bôb""#)
                .fetch_one(&sql_pool)
                .await
                .unwrap();
        assert_eq!(row.column(0).name(), "display_name");
        assert_eq!(row.get::<String, _>("display_name"), "Bob Bobbersön");
        assert_eq!(
            row.get::<NaiveDateTime, _>("creation_date"),
            NaiveDateTime::from_timestamp(0, 0)
        );
    }

    #[actix_rt::test]
    async fn test_already_init_table() {
        let sql_pool = PoolOptions::new().connect("sqlite::memory:").await.unwrap();
        init_table(&sql_pool).await.unwrap();
        init_table(&sql_pool).await.unwrap();
    }
}
