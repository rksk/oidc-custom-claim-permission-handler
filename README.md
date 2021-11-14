# oidc-custom-claim-permission-handler

This entension to add an additional claim with allowed permissions of the user to the OIDC flows of WSO2 Identity Server.

### Steps to deploy

1. Build the component using maven
2. Copy the `org.wso2.permission.claim.handler-1.0.jar` from target directory into `<IS_HOME>/repository/components/dropins/`
3. Add the following into deployment.toml
```
[oauth.oidc.extensions]
claim_callback_handler="org.wso2.custom.claim.PermissionClaimHandler"
```
4. Restart WSO2 IS
