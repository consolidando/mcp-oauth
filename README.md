# oauth 😎

## 📌 Overview

Minimal OAuth 2.0 authorization server for MCP clients, built with Quarkus. It supports:

- Dynamic client registration (DCR)
- Authorization code + PKCE (S256)
- Refresh tokens with rotation
- ES256 access tokens with JWKS publication
- Google OIDC login
- Firestore persistence for users, clients, auth requests, auth codes, and refresh tokens

This service is designed to run as a standalone auth server, separate from your API and MCP server. It targets Google Cloud (Cloud Run + Firestore) out of the box.

## ⚙️ Environment configuration

`.env.example` lists the environment variables used by this project that are not in the repo. Copy it to `.env` and fill in real values. How you load `.env` depends on your operating system. The `.env` file is not committed. The `.bat` helpers used to set the environment or deploy are examples and must be adapted to your system.

### Core OAuth

- `EMP_OAUTH_ISSUER`: Public issuer URL for this auth server.
- `EMP_OAUTH_DEFAULT_RESOURCE`: Default resource/audience if none is provided.
- `EMP_OAUTH_AUTH_CODE_TTL_SECONDS`: Auth code lifetime in seconds.
- `EMP_OAUTH_AUTH_REQUEST_TTL_SECONDS`: Pending auth request lifetime in seconds.
- `EMP_OAUTH_ACCESS_TOKEN_TTL_SECONDS`: Access token lifetime in seconds.
- `EMP_OAUTH_REFRESH_TOKEN_TTL_SECONDS`: Refresh token lifetime in seconds.
- `EMP_OAUTH_AUTO_CONSENT`: If `true`, skip the consent screen after login.
- `EMP_OAUTH_CONSENT_BRAND_NAME`: Brand text shown on the consent page.
- `EMP_OAUTH_CLEANUP_CLIENTS_INACTIVE_DAYS`: Days of inactivity before cleanup removes a client.

### Keys and JWKS (ES256)

- `EMP_OAUTH_PUBLIC_KEY_PATH`: Path to the ES256 public key PEM.
- `EMP_OAUTH_PRIVATE_KEY_SECRET`: Secret Manager resource for the ES256 private key.
- `EMP_OAUTH_PRIVATE_KEY_PATH`: Local fallback for the ES256 private key PEM.
- `EMP_OAUTH_KEY_ID`: `kid` for JWKS and JWT headers.

### Google OIDC

- `EMP_GOOGLE_CLIENT_ID`: OAuth client ID.
- `EMP_GOOGLE_CLIENT_SECRET`: OAuth client secret.
- `EMP_GOOGLE_REDIRECT_URI`: Must be `https://<issuer>/oauth/google/callback`.
- `EMP_GOOGLE_AUTH_ENDPOINT`: Google auth endpoint.
- `EMP_GOOGLE_TOKEN_ENDPOINT`: Google token endpoint.
- `EMP_GOOGLE_JWKS_URI`: Google JWKS endpoint.
- `EMP_GOOGLE_SCOPE`: OAuth scopes for login.

### Firestore

- `EMP_OAUTH_FIRESTORE_ENABLED`: Enable Firestore-backed stores.
- `EMP_OAUTH_FIRESTORE_USERS_COLLECTION`: Users collection name.
- `EMP_OAUTH_FIRESTORE_CLIENTS_COLLECTION`: Clients collection name.
- `EMP_OAUTH_FIRESTORE_AUTH_CODES_COLLECTION`: Auth codes collection name.
- `EMP_OAUTH_FIRESTORE_AUTH_REQUESTS_COLLECTION`: Auth requests collection name.
- `EMP_OAUTH_FIRESTORE_REFRESH_TOKENS_COLLECTION`: Refresh tokens collection name.

### Deployment helpers (optional)

- `EMP_PROJECT_ID`: GCP project id.
- `EMP_REGION`: Cloud Run region.
- `EMP_SERVICE_NAME`: Cloud Run service name.
- `EMP_REPO_NAME`: Artifact Registry repo name.
- `EMP_IMAGE_NAME`: Docker image name.
- `EMP_IMAGE_TAG`: Docker image tag.

## 🚀 Deploy steps (native)

### Set GCP project

```bash
  `gcloud config set project %PROJECT_ID%`
```  
### Build native binary

```bash
  `.\mvnw.cmd package -Dnative -DskipTests -Dquarkus.native.container-build=true`
```  

### Build Docker image

```bash
  `docker build -f src/main/docker/Dockerfile.native -t %REGION%-docker.pkg.dev/%PROJECT_ID%/%REPO_NAME%/%IMAGE_NAME%:%IMAGE_TAG% .`
```  

### Push Docker image

```bash
  `docker push %REGION%-docker.pkg.dev/%PROJECT_ID%/%REPO_NAME%/%IMAGE_NAME%:%IMAGE_TAG%`
```  

### Deploy to Cloud Run

```bash
  `gcloud run deploy %SERVICE_NAME% --image %REGION%-docker.pkg.dev/%PROJECT_ID%/%REPO_NAME%/%IMAGE_NAME%:%IMAGE_TAG% --region %REGION% --platform managed --allow-unauthenticated --env-vars-file env-vars.yaml`
```    

## 🧹 Cleanup endpoint

Call `POST /oauth/cleanup` from a cron job to remove expired auth requests, used/expired auth codes and refresh tokens, and clients inactive for the configured number of days.  


## 📎 References

- OpenAI Apps SDK Auth: <https://developers.openai.com/apps-sdk/build/auth/>
- MCP Authorization Specification: <https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization>
- MCP Inspector Tooling: <https://modelcontextprotocol.io/docs/tools/inspector>

## ⚖ License

This project is licensed under the [CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/) License. See the [LICENSE](LICENSE.md) file for details.