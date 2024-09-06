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
use std::fmt;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ldap3::result::Result;
use ldap3::{LdapConn, LdapConnSettings, Mod, Scope, SearchEntry};
use rand::Rng;
use sha1::{Digest, Sha1};

struct Ldap {
    conn: LdapConn,
    base_dn: String,
}

#[allow(dead_code)]
struct User<'a> {
    uid: &'a str,
    user_password: &'a str,
    cn: &'a str,
    sn: &'a str,
    home_directory: &'a str,
    login_shell: &'a str,
    given_name: &'a str,
    display_name: &'a str,
    uid_number: &'a str,
    gid_number: &'a str,
    gecos: &'a str,
    ou: Groups,
}
#[allow(dead_code)]
enum Groups {
    People,
    Group,
    Other,
}
fn generate_ssha(password: &str) -> String {
    let mut sha = Sha1::new();
    let mut rng = rand::thread_rng();

    // Generate random 4-byte salt
    let salt: [u8; 4] = rng.gen();

    // Write the password and salt to the hash
    sha.update(password.as_bytes());
    sha.update(salt);

    // Get the hash output
    let hashed_password = sha.finalize();

    // Combine the hash and salt
    let mut ssha = Vec::new();
    ssha.extend_from_slice(&hashed_password);
    ssha.extend_from_slice(&salt);

    // Encode the final SSHA result to base64 and wrap with {SSHA} tag using STANDARD engine
    format!("{{SSHA}}{}", STANDARD.encode(ssha))
}

impl fmt::Display for Groups {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ou_str = match self {
            Groups::People => "People",
            Groups::Group => "Group",
            Groups::Other => "Other",
        };
        write!(f, "{}", ou_str)
    }
}
#[allow(dead_code)]
impl Ldap {
    fn new(url: &str, base_dn: &str) -> Result<Self> {
        let conn = LdapConn::with_settings(
            LdapConnSettings::new()
                .set_no_tls_verify(true)
                .set_starttls(true)
                .set_conn_timeout(Duration::new(5, 0)),
            url,
        )?;
        Ok(Self {
            conn,
            base_dn: base_dn.to_string(),
        })
    }

    fn bind(&mut self, admin_dn: &str, admin_password: &str) -> Result<()> {
        self.conn.simple_bind(admin_dn, admin_password)?.success()?;
        Ok(())
    }

    fn add_entry(&mut self, dn: &str, attrs: Vec<(&str, Vec<&str>)>) -> Result<()> {
        let attrs: Vec<(&str, HashSet<&str>)> = attrs
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();
        self.conn.add(dn, attrs)?;
        println!("Entry added successfully: {}", dn);
        Ok(())
    }

    fn modify_entry(&mut self, dn: &str, mods: Vec<Mod<&str>>) -> Result<()> {
        self.conn.modify(dn, mods)?.success()?;
        Ok(())
    }

    fn search_entry(
        &mut self,
        scope: Scope,
        filter: &str,
        attrs: Vec<&str>,
    ) -> Result<Vec<SearchEntry>> {
        let (rs, _res) = self
            .conn
            .search(&self.base_dn, scope, filter, attrs)?
            .success()?;
        let entries: Vec<SearchEntry> = rs.into_iter().map(SearchEntry::construct).collect();
        Ok(entries)
    }
    fn change_password(&mut self, dn: &str, new_password: &str) -> Result<()> {
        let mut password_set = HashSet::new();
        let hashed_password = generate_ssha(new_password);
        password_set.insert(hashed_password.as_str());
        let user_dn = user_dn(dn, &self.base_dn);
        let mods = vec![Mod::Replace("userPassword", password_set)];
        self.modify_entry(&user_dn, mods)?;
        println!("Password modification successful for DN: {}", user_dn);
        match self.verify_password(&user_dn, new_password) {
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

    fn verify_password(&mut self, dn: &str, password: &str) -> Result<()> {
        self.conn.simple_bind(dn, password)?.success()?;
        Ok(())
    }

    fn delete_entry(&mut self, dn: &str) -> Result<()> {
        self.conn.delete(dn)?.success()?;
        println!("Entry deleted successfully: {}", dn);
        Ok(())
    }
    fn add_user(&mut self, user: &User) -> Result<()> {
        let user_dn = user.get_dn(&self.base_dn);
        let hashed_password = generate_ssha(user.user_password);
        println!("Hashed password: {}", hashed_password);
        let attrs = vec![
            (
                "objectClass",
                vec!["inetOrgPerson", "posixAccount", "shadowAccount"],
            ),
            ("cn", vec![user.cn]),
            ("sn", vec![user.sn]),
            ("uid", vec![user.uid]),
            ("userPassword", vec![&hashed_password]),
            ("homeDirectory", vec![user.home_directory]),
            ("loginShell", vec![user.login_shell]),
            ("gecos", vec![user.gecos]),
            ("givenName", vec![user.given_name]),
            ("displayName", vec![user.display_name]),
            ("uidNumber", vec![&user.uid_number]),
            ("gidNumber", vec![&user.gid_number]),
        ];
        let attrs: Vec<(&str, HashSet<&str>)> = attrs
            .into_iter()
            .map(|(attr, values)| (attr, values.into_iter().collect()))
            .collect();
        self.conn.add(&user_dn, attrs)?;
        println!("User added successfully: {}", user_dn);
        Ok(())
    }
    fn del_user(&mut self, uid: &str) -> Result<()> {
        let user_dn = format!("uid={},ou={},{}", uid, Groups::People, self.base_dn);
        self.conn.delete(&user_dn)?.success()?;
        println!("User {} deleted successfully from DN: {}", uid, user_dn);
        Ok(())
    }
    fn check_login(&mut self, uid: &str, password: &str) -> Result<()> {
        let user_dn = format!("uid={},ou={},{}", uid, Groups::People, self.base_dn);
        match self.conn.simple_bind(&user_dn, password)?.success() {
            Ok(_) => {
                println!("Login successful!!");
                Ok(())
            }
            Err(e) => {
                println!("Login failed!!");
                Err(e)
            }
        }
        // println!("User {} logged in successfully.", uid);
        // Ok(())
    }
}

#[allow(dead_code)]
impl<'a> User<'a> {
    pub fn get_dn(&self, base_dn: &str) -> String {
        format!("uid={},ou={},{}", self.uid, self.ou, base_dn)
    }
}
fn user_dn(uid: &str, base_dn: &str) -> String {
    format!("uid={},ou=People,{}", uid, base_dn)
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let bind_dn = std::env::var("BIND_DN").expect("BIND_DN is not set in .env file");
    let bind_pw = std::env::var("BIND_PW").expect("BIND_PW is not set in .env file");
    let bind_ip = std::env::var("BIND_IP").expect("BIND_IP is not set in .env file");
    let base_dn = std::env::var("BASE_DN").expect("BASE_DN is not set in .env file");
    let mut ldap = Ldap::new(&bind_ip, &base_dn)?;
    ldap.bind(&bind_dn, &bind_pw)?;

    // 創建用戶
    // let new_user = User {
    //     uid: "test",
    //     user_password: "test12345678",
    //     cn: "Test User",
    //     sn: "User",
    //     home_directory: "/home/test",
    //     login_shell: "/bin/bash",
    //     given_name: "Test",
    //     display_name: "Test User",
    //     uid_number: "10001",
    //     gid_number: "5000",
    //     gecos: "Test User",
    //     ou: Groups::People,
    // };

    // 添加用戶
    // ldap.add_user(&new_user)?;

    // let ret = ldap.search_entry(
    //     Scope::Subtree,
    //     "(uid=test)",
    //     vec![
    //         "dn",
    //         "cn",
    //         "sn",
    //         "uid",
    //         "uidNumber",
    //         "gidNumber",
    //         "homeDirectory",
    //         "loginShell",
    //         "userPassword",
    //     ],
    // )?;
    // println!("Search result: {:#?}", ret);

    // 删除用户
    // ldap.del_user("test")?;

    // let ret = user_dn("john", &base_dn);
    // println!("Search result: {:#?}", ret);

    // 修改密码
    ldap.change_password("john", "test12345678")?;
    let ret = ldap.search_entry(
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
    println!("Search result: {:#?}", ret);
    ldap.check_login("john", "test12345678")?;
    Ok(())
}
