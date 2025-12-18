# Partner Onboarding Util

## Overview

Onboarding supports the following capabilities:

- **Onboard multiple partners together** or **onboard a single partner** as needed.
- **Generate HTML onboarding result reports**.
- **Upload reports** automatically to **MinIO** or **NFS server**.
- **Create all required Kubernetes secrets and files** in the appropriate namespaces.


## Features

- Automated onboarding through shell scripts.
- Postman collection for manual API-based onboarding.
- Configurable environment and partner definitions.
- HTML reporting and pluggable storage upload.
- Namespace-specific secret creation for each onboarded partner.
- Docker support for containerized execution.


## Prerequisites

- Running MOSIP environment (Keycloak, PMS, IDA, Kernel, Resident).
- Keycloak client with:
    - `GLOBAL_ADMIN`
    - `PARTNER_ADMIN`
    - `ID_AUTHENTICATION`
-  Docker installed.
* If the `ENABLE_INSECURE` environment variable is set to `true`, the script will proceed with downloading an SSL certificate and subsequently provide it for utilization in **Newman** collections and **curl** API calls during execution. This functionality is designed for scenarios where the script is required to be used on a server that possesses self-signed SSL certificates.

## Contribution & Community:

- We welcome contributions from everyone!

- Check [here](https://docs.mosip.io/1.2.0/community/code-contributions) to learn how you can contribute code to this application.

- If you have any questions or run into issues while trying out the application, feel free to post them in the [MOSIP Community](https://community.mosip.io/) — we’ll be happy to help you out.


## License
This project is licensed under the terms of [Mozilla Public License 2.0](LICENSE).

