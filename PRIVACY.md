# AllamSec Privacy Policy

**Last updated: November 16, 2026**

## 1. Overview

AllamSec is an open-source cybersecurity monitoring and threat detection application designed to help users analyze security events, identify suspicious activity, and review security alerts.

This policy describes the application's known data-handling behavior.

## 2. Information Processed

Depending on the enabled features and available data sources, AllamSec may process:

- System and Windows event logs
- Authentication and security events
- IP addresses and usernames
- Security alerts, detection results, and risk scores
- Notification delivery records and error information

Security logs may contain sensitive information. Users should ensure they have authorization to monitor the systems and data they analyze.

## 3. Local Data Storage

AllamSec uses a local database to store security information, including alerts and notification history.

Users are responsible for securing their computer and protecting access to stored security information.

## 4. Dashboard Access

By default, the AllamSec dashboard is configured to listen on `127.0.0.1`, restricting direct access to the local computer.

Users who modify the dashboard's network configuration are responsible for implementing appropriate access controls and network security protections.

## 5. Optional Email Notifications

AllamSec supports optional email notifications through a user-configured SMTP server.

When email notifications are enabled, alert messages may include:

- Alert type
- Severity
- Source IP address
- Username
- Risk score

These details are transmitted to the configured SMTP server and delivered to the designated recipient.

Email service providers may process or retain transmitted messages according to their own policies.

SMTP credentials are read from environment variables.

## 6. Application Logs

AllamSec may record operational messages, notification previews, and errors in application logs.

Notification previews may include security alert information such as usernames and IP addresses.

Users should protect application logs from unauthorized access.

## 7. Data Retention and Deletion

Security information may remain in local databases and application logs until it is removed through available application functions or by the user.

Users should review and back up their data before deleting application files.

## 8. Third-Party Services

AllamSec supports integration with user-configured SMTP email services.

Use of an external email provider is subject to that provider's applicable privacy and data-handling policies.

## 9. Security

AllamSec uses TLS for its SMTP email connection and is configured to run its dashboard locally by default.

No software can guarantee complete security. Users should maintain appropriate system protections and restrict access to sensitive security information.

## 10. Changes to This Policy

This policy may be updated as AllamSec develops or additional functionality is introduced.

Updates will be published in the project's GitHub repository.

## 11. Contact

For privacy-related questions, open an issue in the AllamSec GitHub repository:

https://github.com/KareemAllam123/AllamSec/issues