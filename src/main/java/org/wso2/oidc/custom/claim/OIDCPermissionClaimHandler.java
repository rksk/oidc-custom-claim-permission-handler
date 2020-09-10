package org.wso2.oidc.custom.claim;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.openidconnect.DefaultOIDCClaimsCallbackHandler;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.apache.commons.collections.MapUtils.isNotEmpty;

/**
 * Custom OIDC Claim handler to return permissions.
 */
public class OIDCPermissionClaimHandler extends DefaultOIDCClaimsCallbackHandler {

    private static final Log log = LogFactory.getLog(OIDCPermissionClaimHandler.class);
    private static final String OAUTH2 = "oauth2";
    private static final String LOCAL_DIALECT = "http://wso2.org/claims";
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";
    private static final String PERMISSION_CLAIM = "http://wso2.org/claims/permission";
    private static final String PERMISSION_PATH = "/permission";
    private static final String SUPER_ADMIN_PERMISSION_PATH = "/permission/protected";
    private static final String ADMIN_PERMISSION_PATH = "/permission/admin";
    private static final String APPLICATION_PERMISSION_PATH = "/permission/applications";
    private static final String SUPER_ADMIN_PERMISSION = "protected";
    private static final String ADMIN_PERMISSION = "admin";
    private static final String APPLICATION_PERMISSION = "applications";
    private static final String OTHER_PERMISSION = "other";

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                           OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Handling custom claims in OAuth token request.");
        }
        AuthenticatedUser authenticatedUser = tokenReqMessageContext.getAuthorizedUser();
        if (authenticatedUser == null) {
            log.error("Authenticated user not found.");
        } else {
            String userName = authenticatedUser.toFullQualifiedUsername();
            String userTenantDomain = authenticatedUser.getTenantDomain();
            String spTenantDomain = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain();
            String clientId = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId();
            String[] requestedScopes = tokenReqMessageContext.getScope();
            if (log.isDebugEnabled()) {
                log.debug("Handling custom claims for user: " + userName + " in tenant: " + userTenantDomain + " for " +
                        "the SP: " + clientId + " in " + spTenantDomain + ".");
            }

            handleUserPermissions(jwtClaimsSetBuilder, userName, userTenantDomain, spTenantDomain, clientId,
                    requestedScopes);
        }
        return super.handleCustomClaims(jwtClaimsSetBuilder, tokenReqMessageContext);
    }

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                           OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Handling custom claims in Authorization request.");
        }
        AuthenticatedUser authenticatedUser = authzReqMessageContext.getAuthorizationReqDTO().getUser();
        if (authenticatedUser == null) {
            log.error("Authenticated user not found.");
        } else {
            String userName = authenticatedUser.toFullQualifiedUsername();
            String userTenantDomain = authenticatedUser.getTenantDomain();
            String spTenantDomain = authzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
            String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
            String[] requestedScopes = authzReqMessageContext.getAuthorizationReqDTO().getScopes();
            if (log.isDebugEnabled()) {
                log.debug("Handling custom claims for user: " + userName + " in tenant: " + userTenantDomain + " for " +
                        "the SP: " + clientId + " in " + spTenantDomain + ".");
            }

            handleUserPermissions(jwtClaimsSetBuilder, userName, userTenantDomain, spTenantDomain, clientId,
                    requestedScopes);
        }
        return super.handleCustomClaims(jwtClaimsSetBuilder, authzReqMessageContext);
    }

    private void handleUserPermissions(JWTClaimsSet.Builder jwtClaimsSetBuilder, String userName,
                                       String userTenantDomain, String spTenantDomain,
                                       String clientId, String[] requestedScopes) {

        try {
            UserRealm realm = IdentityTenantUtil.getRealm(userTenantDomain, userName);
            if (realm == null) {
                throw new IdentityException("User realm is empty.");
            }
            List<String> userClaimsInOidcDialect =
                    getUserClaimsInOidcDialect(spTenantDomain, clientId, requestedScopes);
            if (log.isDebugEnabled()) {
                if (userClaimsInOidcDialect.isEmpty()) {
                    log.debug("OIDC claim URIs not found.");
                } else {
                    log.debug("OIDC claim URIs: " + userClaimsInOidcDialect.toString());
                }
            }

            Map<String, List<String>> permissionList =
                    createPermissionStructure(userClaimsInOidcDialect, userName, realm);

            if (!permissionList.isEmpty()) {
                jwtClaimsSetBuilder.claim("permissions", permissionList);
            }
        } catch (IdentityApplicationManagementException e) {
            log.error(
                    "Error while obtaining service provider for tenant domain: " + spTenantDomain + " client id: "
                            + clientId, e);
        } catch (IdentityException e) {
            log.error("Error while obtaining user realm for for user: " + userName + " in tenant domain: " +
                    userTenantDomain, e);
        }
    }

    private ServiceProvider getServiceProvider(String spTenantDomain,
                                               String clientId) throws IdentityApplicationManagementException {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        String spName = applicationMgtService.getServiceProviderNameByClientId(clientId, OAUTH2, spTenantDomain);

        if (log.isDebugEnabled()) {
            log.debug("Retrieving service provider for clientId: " + clientId + " in tenantDomain: " + spTenantDomain);
        }
        return applicationMgtService.getApplicationExcludingFileBasedSPs(spName, spTenantDomain);
    }

    private ClaimMapping[] getRequestedClaimMappings(ServiceProvider serviceProvider) {

        if (serviceProvider.getClaimConfig() == null) {
            return new ClaimMapping[0];
        }
        return serviceProvider.getClaimConfig().getClaimMappings();
    }

    private List<String> getRequestedClaimUris(ClaimMapping[] requestedLocalClaimMap) {

        List<String> claimURIList = new ArrayList<>();
        for (ClaimMapping mapping : requestedLocalClaimMap) {
            if (mapping.isRequested()) {
                claimURIList.add(mapping.getLocalClaim().getClaimUri());
            }
        }
        return claimURIList;
    }

    private List<String> getUserClaimsInOidcDialect(String spTenantDomain, String clientId, String[] requestedScopes)
            throws IdentityApplicationManagementException, ClaimMetadataException {

        Map<String, Object> userClaimsInOidcDialect = new HashMap<>();
        ServiceProvider serviceProvider = getServiceProvider(spTenantDomain, clientId);
        ClaimMapping[] requestClaimMappings = getRequestedClaimMappings(serviceProvider);

        List<String> requestedClaimUris = getRequestedClaimUris(requestClaimMappings);
        // Retrieve OIDC to Local Claim Mappings.
        Map<String, String> oidcToLocalClaimMappings = ClaimMetadataHandler.getInstance()
                .getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, null, spTenantDomain, false);
        if (!requestedClaimUris.isEmpty()) {
            // Map<"email", "http://wso2.org/claims/emailaddress">
            for (Map.Entry<String, String> claimMapping : oidcToLocalClaimMappings.entrySet()) {
                if (requestedClaimUris.contains(claimMapping.getValue())) {
                    userClaimsInOidcDialect.put(claimMapping.getKey(), claimMapping.getValue());
                }
            }
        }

        Map<String, Object> filteredUserClaimsInOidcDialect = filterClaimsByScope(userClaimsInOidcDialect,
                requestedScopes, clientId, spTenantDomain);

        return getFilteredClaimUris(filteredUserClaimsInOidcDialect);
    }

    private List<String> getFilteredClaimUris(Map<String, Object> filteredUserClaimsInOidcDialect) {

        List<String> claimURIList = new ArrayList<>();
        if (isNotEmpty(filteredUserClaimsInOidcDialect)) {
            for (Map.Entry<String, Object> filteredClaim : filteredUserClaimsInOidcDialect.entrySet()) {
                if (filteredClaim.getValue() != null) {
                    claimURIList.add(filteredClaim.getValue().toString());
                }
            }
        }
        return claimURIList;
    }

    private Map<String, List<String>> createPermissionStructure(List<String> userClaimsInOidcDialect, String userName,
                                                                UserRealm realm) {

        Map<String, List<String>> permissionList = new HashMap<>();
        Set<String> superAdminPermissionList = new HashSet<>();
        Set<String> adminPermissionList = new HashSet<>();
        Set<String> applicationPermissionList = new HashSet<>();
        Set<String> otherPermissionList = new HashSet<>();

        try {
            AuthorizationManager authorizationManager = realm.getAuthorizationManager();

            for (String claimUri : userClaimsInOidcDialect) {
                if (claimUri.contains(PERMISSION_CLAIM)) {
                    String permissionRootPath = claimUri.replace(LOCAL_DIALECT, "");
                    if (log.isDebugEnabled()) {
                        log.debug("Retrieving permissions for " + permissionRootPath);
                    }
                    String[] permissions = authorizationManager
                            .getAllowedUIResourcesForUser(MultitenantUtils.getTenantAwareUsername(userName),
                                    permissionRootPath);
                    if (log.isDebugEnabled()) {
                        if (ArrayUtils.isEmpty(permissions)) {
                            log.debug("Permission list is empty for " + permissionRootPath);
                        } else {
                            log.debug("Retrieved permission list for " + permissionRootPath + ": " +
                                    Arrays.asList(permissions));
                        }
                    }

                    for (String permission : permissions) {
                        if (permission.contains(SUPER_ADMIN_PERMISSION_PATH)) {
                            superAdminPermissionList.add(getPermissionLeaf(SUPER_ADMIN_PERMISSION_PATH, permission));
                        } else if (permission.contains(ADMIN_PERMISSION_PATH)) {
                            adminPermissionList.add(getPermissionLeaf(ADMIN_PERMISSION_PATH, permission));
                        } else if (permission.contains(APPLICATION_PERMISSION_PATH)) {
                            applicationPermissionList.add(getPermissionLeaf(APPLICATION_PERMISSION_PATH, permission));
                        } else {
                            otherPermissionList.add(getPermissionLeaf(PERMISSION_PATH, permission));
                        }
                    }
                }
            }
            if (!superAdminPermissionList.isEmpty()) {
                permissionList.put(SUPER_ADMIN_PERMISSION, new ArrayList<>(superAdminPermissionList));
            }
            if (!adminPermissionList.isEmpty()) {
                permissionList.put(ADMIN_PERMISSION, new ArrayList<>(adminPermissionList));
            }
            if (!applicationPermissionList.isEmpty()) {
                permissionList.put(APPLICATION_PERMISSION, new ArrayList<>(applicationPermissionList));
            }
            if (!otherPermissionList.isEmpty()) {
                permissionList.put(OTHER_PERMISSION, new ArrayList<>(otherPermissionList));
            }

        } catch (UserStoreException e) {
            log.error("Error while retrieving user claim in local dialect for user: " + userName, e);
        }
        return permissionList;
    }

    private String getPermissionLeaf(String path, String permission) {

        permission = permission.replace(path, "");
        if (StringUtils.isEmpty(permission)) {
            permission = "/";
        }
        return permission;
    }
}
