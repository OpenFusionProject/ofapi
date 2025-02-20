# ofapi

ofapi is an API server that provides RESTful web APIs to enhance [OpenFusion](https://github.com/OpenFusionProject/OpenFusion) server instances.

ofapi groups available APIs into modules. Each module has a corresponding table in the config file (`config.toml`) and can be deactivated by commenting out the table (with the exception of the `core` and `game` modules, which are required).

Some modules are "secure", meaning their APIs must be accessed by the TLS port bound to by the application. TLS can be applied at the application level by compiling with the `tls` [feature](https://doc.rust-lang.org/cargo/reference/features.html) or by a proxy server such as [nginx](https://nginx.org/). **Please verify that secure APIs are only accessible through TLS before deploying ofapi on a publicly accessible network.**

ofapi requires an OpenFusion sqlite database of version 6 or higher.

## Developing
Edit `config.toml` to your liking and then
```
cargo run
```

## Production
```
cargo build --release
./target/release/ofapi
```

## Modules & APIs
| Module     | Required | Secure | Description |
|------------|----------|--------|-------------|
| core       | Yes      | No     | Core functionality of the API server |
| tls        | No*      | N/A    | TLS configuration for secure APIs |
| email      | No       | N/A    | SMTP configuration for sending emails |
| game       | Yes      | No     | Game version and login address info |
| monitor    | No       | No     | Real-time game data |
| moderation | No       | Yes    | Game moderation tools, such as name requests |
| rankinfo   | No*      | No     | Infected Zone race ranking info |
| account    | No       | Yes    | User account management APIs |
| auth       | No*      | Yes    | Authentication and authorization APIs |
| cookie     | No*      | Yes    | Secure game login |
| legacy     | No       | No     | Compatibility with legacy, file-based clients |
| static     | N/A      | No     | Static resource serving |

\*Module highly recommended

### Module APIs

| Module     | Endpoints                | Method | Authed | Description |
|------------|--------------------------|--------|--------|-------------|
| core       | /                        | GET    | No     | Basic info about ofapi and OpenFusion configuration |
| monitor    | /status                  | GET    | No     | Real-time game data (e.g. player count) |
| moderation | /namereq                 | GET    | Yes    | Get a list of pending player name requests |
|            |                          | POST   | Yes    | Approve or deny a player name request |
| rankinfo   | /getranks                | POST   | No     | Rank info for an Infected Zone (game format) |
| account    | /account                 | GET    | Yes    | Basic user account info |
|            | /account/register        | POST   | No     | Register a user account |
|            | /account/verify          | GET    | No     | Verify an email address for an account |
|            | /account/update/password | POST   | Yes    | Update the password for an account |
|            | /account/update/email    | POST   | Yes    | Update the email for an account |
| auth       | /auth                    | POST   | No     | Obtain a refresh token for an account |
|            | /auth/session            | POST   | Yes*   | Obtain a session token for an account |
| cookie     | /cookie                  | POST   | Yes    | Obtain an OpenFusion login cookie for an account |
| legacy     | /index.html              | GET    | No     | Get an index.html file for legacy client use |
|            | /assetInfo.php           | GET    | No     | Get an assetInfo.php file for legacy client use |
|            | /loginInfo.php           | GET    | No     | Get a loginInfo.php file for legacy client use |
| static     | /*                       | GET    | No     | See `statics.csv`

\*Auth by refresh token instead of session token

Technical documentation on each API is WIP and will be on the GitHub wiki.

## Static Resources
Static files and directories can be easily served by mapping them to an endpoint in the `statics.csv` file.
These are accessible from both HTTP and HTTPS. Some common mappings are included as defaults.

## Authentication
ofapi uses capability-based [JSON Web Tokens ("jwt")](https://jwt.io/) for authentication.
A secret key is generated on first startup (see the config for the `auth` module) and is used for token signing.
All tokens can be invalidated by deleting and regenerating the secret file. **Do not share this file with anyone.**

### Refresh Tokens
Refresh tokens are used to generate new session tokens. They should be long-lived and cached by clients, and are invalidated upon password changes. Refresh tokens have a single capability: acquiring a session token.

### Session Tokens
Session tokens are multi-capable and can access most authed module APIs, with the exception of those requiring extra capabilities (such as the moderation APIs). They should be very short-lived and reacquired using a refresh token.

### Service Tokens
Service tokens are special tokens that are manually created using the `gen_token` binary in the Cargo project. The lifespan and capabilities of service tokens are completely customizable and are meant to be used by external services such as [Discord bots](https://github.com/OpenFusionProject/computress-rs).

#### Generation
You can run `gen_token` with Cargo like so:
```
cargo run --bin=gen_token
```
An interactive prompt will guide you through the token creation process.
