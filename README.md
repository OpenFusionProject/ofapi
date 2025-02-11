# ofapi

ofapi is an API server that provides RESTful web APIs to enhance [OpenFusion](https://github.com/OpenFusionProject/OpenFusion) server instances.

ofapi groups available APIs into modules. Each module has a corresponding table in the config file (`config.toml`) and can be deactivated by commenting out the table (with the exception of the `core` and `game` modules, which are required).

Many APIs are "secure", meaning they must be accessed by the TLS port bound to by the application. TLS can be applied at the application level by compiling with the `tls` [feature](https://doc.rust-lang.org/cargo/reference/features.html) or by a proxy server such as [nginx](https://nginx.org/). **Please verify that secure APIs are only accessible through TLS before deploying ofapi on a publicly accessible network.**

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
### Available Modules

| Module     | Description | Required |
|------------|-------------|----------|
| core       | Core functionality of the API server | Yes |
| tls        | TLS configuration for secure APIs | No* |
| email      | SMTP configuration for sending emails | No |
| game       | Game version and login address info | Yes |
| monitor    | Real-time game data | No |
| moderation | Game moderation tools, such as name requests | No |
| rankinfo   | Infected Zone race ranking info | No* |
| account    | User account management APIs | No |
| auth       | Authentication and authorization APIs | No* |
| cookie     | Secure game login | No* |
| legacy     | Compatibility with legacy, file-based clients | No |
| static     | Static resource serving | N/A |

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
|            | /auth/session            | POST   | Yes    | Obtain a session token for an account |
| cookie     | /cookie                  | POST   | Yes    | Obtain an OpenFusion login cookie for an account |
| legacy     | /index.html              | GET    | No     | Get an index.html file for legacy client use |
|            | /assetInfo.php           | GET    | No     | Get an assetInfo.php file for legacy client use |
|            | /loginInfo.php           | GET    | No     | Get a loginInfo.php file for legacy client use |
| static     | /*                       | GET    | No     | See `statics.csv`

Technical documentation on each API is WIP and will be on the GitHub wiki.
