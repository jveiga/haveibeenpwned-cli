use log::*;
use minreq::get;
use sha::sha1::Sha1;
use sha::utils::{Digest, DigestExt};
use std::error::Error;

fn check_haveibeenpwned(pass: &str) -> Result<String, minreq::Error> {
    let url = format!("https://api.pwnedpasswords.com/range/{}", pass);
    info!("Requesting to {}", url);

    let response = get(&url).send()?;

    response.as_str().map(|s| s.to_string())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args();
    let _ = args.next(); // ignore command name

    if args.len() == 0 {
        eprintln!("no passwords given");
        return Ok(());
    }

    while let Some(pass) = args.next() {
        debug!("finding {}", &pass);
        let password_hash = Sha1::default().digest(pass.as_bytes()).to_hex();
        info!("hashed password {:?}", &password_hash);
        let hash_slice = password_hash[0..5].to_uppercase();
        let hash_slice2 = password_hash[5..].to_uppercase();
        info!("first chars of hashed password {:?}", hash_slice);

        if let Ok(response) = check_haveibeenpwned(&hash_slice){
            if let Some(res) = response
                // .lines()
                .split("\r\n")
                .map(|line| {
                    let line_split = line.split(':').collect::<Vec<&str>>();

                    (line_split[0], line_split[1])
                })
                .find(|(hash, _pass)| *hash == hash_slice2)
            {
                println!("Found password {}, {} times", pass.to_uppercase(), res.1);
            } else {
                eprintln!("Password not found");
            }
        }
    }

    Ok(())
}
