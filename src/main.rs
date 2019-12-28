use reqwest::get;
use sha::sha1::Sha1;
use sha::utils::{Digest, DigestExt};
use std::error::Error;
use tokio;

async fn check_haveibeenpwned(pass: &str) -> Result<String, reqwest::Error> {
    let url = format!("https://api.pwnedpasswords.com/range/{}", pass);
    println!("Requesting to {}", url);

    let text_response = get(url.as_str()).await?.text().await;
    println!("{:?}", &text_response);

    text_response
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args();
    let _ = args.next(); // ignore command name

    if let Some(pass) = args.next() {
        let password_hash = Sha1::default().digest(pass.as_bytes()).to_hex();
        println!("hashed password {:?}", &password_hash);
        let hash_slice = password_hash[0..5].to_uppercase();
        let hash_slice2 = password_hash[5..].to_uppercase();
        println!("first chars of hashed password {:?}", hash_slice);

        if let Ok(response) = check_haveibeenpwned(hash_slice.as_str()).await {
            if let Some(res) = response
                .split("\r\n")
                .map(|line| {
                    let line_split = line.split(":").collect::<Vec<&str>>();

                    PasswordResult(line_split[0], line_split[1])
                })
                .find(|result| result.0 == hash_slice2)
            {
                println!("Found password {}, {} times", pass.to_uppercase(), res.1);
            } else {
                println!("Password not found");
            }
        }
    } else {
        eprintln!("No args given");
    }

    Ok(())
}

struct PasswordResult<'a>(&'a str, &'a str);
