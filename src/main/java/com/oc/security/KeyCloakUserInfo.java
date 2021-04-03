package com.oc.security;

import java.util.List;

import org.keycloak.AuthorizationContext;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.idm.authorization.Permission;

/**
 * @author cksek
 *
 */
public class KeyCloakUserInfo {

	private final KeycloakSecurityContext securityContext;
	
	public KeyCloakUserInfo(KeycloakSecurityContext securityContext) {
		this.securityContext = securityContext;
	}
	
	/**
	 * Return name for current logged user
	 * @return
	 */
	public String getName() {
		
		String name = "";
		
		if (securityContext != null) {
			name = securityContext.getIdToken().getPreferredUsername();
		}
		
		return name;
	}
	
	/**
	 * Return name for current logged user
	 * @return
	 */
	public String getAccessToken() {
		
		String access_token = "";
		
		if (securityContext != null) {
			access_token = securityContext.getTokenString();
		}
		
		return access_token;
	}
	
	/**
	 * Return assigned permission for current user
	 * @return
	 */
	public List<Permission> getUserPermission() {
		return securityContext.getAuthorizationContext().getPermissions();
	}
	
	/**
	 * Return authorization context for current user
	 * @return
	 */
	public AuthorizationContext getUserAuthorizationContext() {
		return securityContext.getAuthorizationContext();
	}
	
}
