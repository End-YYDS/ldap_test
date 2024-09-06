// use std::time::Duration;
// use dotenv::dotenv;
// use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
// use serde::{Deserialize, Serialize};
// use serde_json::{from_str, to_string};

// #[derive(Debug, Serialize, Deserialize)]
// struct LdapUser {
//     dn: String,
//     cn: Option<String>,
//     sn: Option<String>,
//     uid: Option<String>,
//     uid_number: Option<String>,
//     gid_number: Option<String>,
//     home_directory: Option<String>,
//     login_shell: Option<String>,
// }

// impl LdapUser {
//     fn from_search_entry(entry: SearchEntry) -> Self {
//         let dn = entry.dn;
//         let cn = entry.attrs.get("cn").and_then(|vals| vals.first().cloned());
//         let sn = entry.attrs.get("sn").and_then(|vals| vals.first().cloned());
//         let uid = entry
//             .attrs
//             .get("uid")
//             .and_then(|vals| vals.first().cloned());
//         let uid_number = entry
//             .attrs
//             .get("uidNumber")
//             .and_then(|vals| vals.first().cloned());
//         let gid_number = entry
//             .attrs
//             .get("gidNumber")
//             .and_then(|vals| vals.first().cloned());
//         let home_directory = entry
//             .attrs
//             .get("homeDirectory")
//             .and_then(|vals| vals.first().cloned());
//         let login_shell = entry
//             .attrs
//             .get("loginShell")
//             .and_then(|vals| vals.first().cloned());

//         LdapUser {
//             dn,
//             cn,
//             sn,
//             uid,
//             uid_number,
//             gid_number,
//             home_directory,
//             login_shell,
//         }
//     }
// }

// fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
//     dotenv().ok();
//     let mut ldap = LdapConn::with_settings(
//         LdapConnSettings::new()
//             .set_no_tls_verify(true)
//             .set_starttls(true)
//             .set_conn_timeout(Duration::new(5, 0)),
//         "ldap://172.20.10.12:389",
//     )?;
//     let bind_dn = std::env::var("BIND_DN").expect("BIND_DN is not set in .env file");
//     let bind_pw = std::env::var("BIND_PW").expect("BIND_PW is not set in .env file");
//     ldap.simple_bind(&bind_dn, &bind_pw)?.success()?;

//     let (rs, _res) = ldap
//         .search(
//             "dc=example,dc=com", // 基準點
//             Scope::Subtree,      // 搜索範圍
//             "(uid=john)",        // 搜尋過濾條件
//             vec![
//                 "dn",
//                 "cn",
//                 "sn",
//                 "uid",
//                 "uidNumber",
//                 "gidNumber",
//                 "homeDirectory",
//                 "loginShell",
//             ], // 要回傳的屬性
//         )?
//         .success()?;

//     for entry in rs {
//         let entry = SearchEntry::construct(entry);
//         let user = LdapUser::from_search_entry(entry);

//         let json = to_string(&user)?;
//         println!("Serialized JSON: {}", json);

//         let deserialized_user: LdapUser = from_str(&json)?;
//         println!("Deserialized User: {:?}", deserialized_user);
//     }
//     ldap.unbind()?;

//     Ok(())
// }

use dotenv::dotenv;
use std::collections::HashSet;
use std::time::Duration;

use ldap3::result::Result;
use ldap3::{LdapConn, LdapConnSettings, Mod, Scope, SearchEntry};

fn ldap_connect(url: &str) -> Result<LdapConn> {
    let conn = LdapConn::with_settings(
        LdapConnSettings::new()
            .set_no_tls_verify(true)
            .set_starttls(true)
            .set_conn_timeout(Duration::new(5, 0)),
        url,
    )?;
    Ok(conn)
}

fn ldap_bind(ldap: &mut LdapConn, admin_dn: &str, admin_password: &str) -> Result<()> {
    ldap.simple_bind(admin_dn, admin_password)?.success()?;
    Ok(())
}

fn ldap_add_entry(ldap: &mut LdapConn, base_dn: &str, attrs: Vec<(&str, Vec<&str>)>) -> Result<()> {
    let attrs: Vec<(&str, HashSet<&str>)> = attrs
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().collect()))
        .collect();
    ldap.add(base_dn, attrs)?;
    Ok(())
}

fn ldap_modify_entry(ldap: &mut LdapConn, base_dn: &str, mods: Vec<Mod<&str>>) -> Result<()> {
    ldap.modify(base_dn, mods)?;
    Ok(())
}
fn ldap_search_entry(
    ldap: &mut LdapConn,
    base_dn: &str,
    scope: Scope,
    filter: &str,
    attrs: Vec<&str>,
) -> Result<Vec<SearchEntry>> {
    let (rs, _res) = ldap.search(base_dn, scope, filter, attrs)?.success()?;
    let entries: Vec<SearchEntry> = rs.into_iter().map(SearchEntry::construct).collect();
    Ok(entries)
}
fn ldap_change_password(ldap: &mut LdapConn, dn: &str, new_password: &str) -> Result<()> {
    let mut password_set = HashSet::new();
    password_set.insert(new_password);
    let mods = vec![Mod::Replace("userPassword", password_set)];
    ldap_modify_entry(ldap, dn, mods)?;
    println!("Password modification successful for DN: {}", dn);
    match verify_password(ldap, dn, new_password) {
        Ok(_) => {
            println!("Password verification successful: Password changed and works.");
            Ok(())
        }
        Err(e) => {
            println!("Password verification failed: {}", e);
            Err(e)
        }
    }
}
fn verify_password(ldap: &mut LdapConn, dn: &str, password: &str) -> Result<()> {
    ldap.simple_bind(dn, password)?.success()?;
    Ok(())
}
fn user_dn(uid: &str, gid: &str, base_dn: &str) -> String {
    format!("uid={},ou={},{}", uid, gid, base_dn)
}
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let bind_dn = std::env::var("BIND_DN").expect("BIND_DN is not set in .env file");
    let bind_pw = std::env::var("BIND_PW").expect("BIND_PW is not set in .env file");
    let bind_ip = std::env::var("BIND_IP").expect("BIND_IP is not set in .env file");
    let base_dn = std::env::var("BASE_DN").expect("BASE_DN is not set in .env file");
    let mut ldap = ldap_connect(&bind_ip)?;
    ldap_bind(&mut ldap, &bind_dn, &bind_pw)?;
    let ret = ldap_search_entry(
        &mut ldap,
        &base_dn,
        Scope::Subtree,
        "(uid=john)",
        vec![
            "dn",
            "cn",
            "sn",
            "uid",
            "uidNumber",
            "gidNumber",
            "homeDirectory",
            "loginShell",
            "userPassword",
        ],
    )?;
    // println!("{:?}", ret);
    ldap_change_password(
        &mut ldap,
        &user_dn("john", "People", &base_dn),
        "test12345678",
    )?;
    Ok(())
}
