# Safe Demo App

A well-built project. The backend validates every request and enforces row-level
security on all tables. Secrets are loaded from environment variables at runtime and
never shipped to the client.

## Setup

Set your environment variables in a local `.env` (gitignored). The app authenticates
every user and checks object ownership before returning data.
