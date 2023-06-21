use std::collections::HashMap;
use std::error::Error;

use jwt_simple::prelude::*;
use log;

const SUBJECT: &'static str = "fba8ce10-6689-439e-9344-c62cd1a1040f";
const AUDIENCE: &'static str = "/sso/oauth2/realms/root/realms/api/access_token";
const ISSUER: &'static str = "fba8ce10-6689-439e-9344-c62cd1a1040f";
const REDIRECT_URL: &'static str = "/sso/";
const GRANT_TYPE: &'static str = "client_credentials";
const CLIENT_ASSERTION_TYPE: &'static str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const PRIVATE_KEY_PEM: &'static str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA4W8R3BGGQtKuNufJskRY9pNUrIxhfkfVbzmcLm28rmY4YHRq
Vg5PUpzqfCrMFWk5N5385nbQUeFA8rnhPelXGTFGcYZdsoK/ZHIWgUn2y2kpy6af
CYykDRqMeGotahVNlve+/nG94uvOMfDHb3UYP3RTsU3LtM0sQmfjmp9TEZMW/m4q
EBMatTPpUcSR6GOtWmcJjO1Cb6XJXxmVXyDPnG6kiJB4m/c2VeG+3aLAXvea341c
D1Z8guvse3n4U0NLPwXD+eyKLUT2pX3SOf8Xi/8IsGTbfXAEYRJ0zqrBq/AH04a5
b4Z34wT2KjYPlZeQ0iSa6hiqQMb5INaqnoLKrwIDAQABAoIBACXZi7Ka4KN8kxKV
5TgAoL05rGhSI5Zbwjqr/gyPkTPo5sNPGIF9YpUY0ofpeZ2IrronVQxu23g77Tcz
vV0zPdP1gYHTEQ1FRZQ8UYoAnKa3b/SI87/bNLocgIRBM4HRtNbJnvBCsaKVe+fH
qPyOOPWCdwDYcoDXR/yYS88su/pBmtYGe+zNixFd2vpbBmvXo0oVEupnkfBAfq3E
D/AZt5oP8Y5GqrQk4JzscnTHJYuPaMAGQjQDPy9GzdKx8JjDTmsEWgSYwi7Eq9z3
Qjz/Yy5wXb3EWgjJt0IKB900n9F7dN8FaSnWz/PgDrRvcGcxqFAWGr7AgB1AvEkW
MWce1VECgYEA9NuSCbDcCGhZ8usGaAiv7Ma5mU8nN/RXngZUMR01ptHyOaCCK6gy
EBbk4nKNxIx8RRL5mL51JqZNJttB5SyrFUBmzT4e0lVX7MQAgZbvfCrczEtbeYza
8dVbunt23QAPYR97P70g7LAMI7lSE2FjO6v/1aLJ5a5zE1cESFYFjX8CgYEA67E5
fcmD35J/ecObNm22WtsSALspktsCQZUUr87PTlioyyByIfBlDsCwxkmosA3JQVDI
PoXVUHO6j2H9ZJMeMRP+2dzPhr3Kbamgaui/03PxUP42oGph0V+nd9DKCRRDPczr
p99qZj/ZXY5gQrrK/LBFlCJGdCA2/VNMD9LUutECgYBpU5YDQyezGigvHTgZQjti
z60ArJLDOAEEgdZvdhAhHUhjz46O9v/p+d8lJX+kH4ZJNDtXn/3GzVx8rW4wBcHm
F1jhSqp5caqrtzg8hk+oCswFuRi1NYjs5AlcM0XTFPaIocEjjth919CxAUO0AH1u
KrOXEzpj6WGo3RKDhzVGQwKBgDRfjlnwRJiSsjb5i2z91i68TXTSIjva5NZz7UPf
3dsYAnIYxKPcCmjL0rxNM+njNlyIOecC0FLvVH52FNubgXMAcXoyAf97/xZ9QgNf
svim4/HOe48L9K6U5d7PC4YW9ZYvChKkp70O5RtP/v31ChQ6i0uOjj9RxUZnkxhV
DiZxAoGANtbSVfFfEPO5nHqdgeD4zFmOaUImt+1AZ0gtToYTM49b3+KT+sK6dXA/
/9lZJQIfdOl27MZ5TI2j7ckkvB9m/ySNabv8wg9kPthAYN22Y+Dx6imqn2QfwWN+
yJg4Gr37vy7/zwGlQYfNsOFqBd9SmevNzIjktqW7BK5TzoNXztE=
-----END RSA PRIVATE KEY-----
"#;

#[derive(Deserialize)]
struct ResponsePayload {
    access_token: String,
    scope: String,
    token_type: String,
    expires_in: u16,
}

pub async fn get_jwt(scope: &str, url: &str) -> Result<String, Box<dyn Error>> {
    let key_pair = RS256KeyPair::from_pem(PRIVATE_KEY_PEM)?;
    let audience = format!("{}{}", url, AUDIENCE);
    let endpoint = format!("{}{}", url, AUDIENCE);
    let redirect_url = format!("{}{}", url, REDIRECT_URL);

    let claims = Claims::create(Duration::from_mins(1))
        .with_issuer(ISSUER)
        .with_audience(audience)
        .with_subject(SUBJECT);

    let token = key_pair.sign(claims)?;

    log::debug!("client token: {token}");

    let mut payload = HashMap::new();
    payload.insert("grant_type", GRANT_TYPE);
    payload.insert("redirect_uri", &redirect_url);
    payload.insert("scope", scope);
    payload.insert("client_assertion_type", CLIENT_ASSERTION_TYPE);
    payload.insert("client_assertion", token.as_str());

    let http_client = reqwest::Client::builder().build()?;
    let response = http_client.post(endpoint).form(&payload).send().await?;

    let response_payload = response.json::<ResponsePayload>().await?;

    Ok(response_payload.access_token)
}
