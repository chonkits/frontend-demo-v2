/**
 * 
 */
package com.oc.controller;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.json.JSONObject;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.TokenVerifier;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.JsonWebToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;

import com.oc.security.KeyCloakUserInfo;

/**
 * @author cksek
 *
 */
@Controller
public class AppController {

	@Value("${trust.store}")
	private Resource trustStore;

	@Value("${trust.store.password}")
	private String trustStorePassword;

	@Value("${keycloak.realm}")
	private String configuredRealm;

	@Value("${keycloak.auth-server-url}")
	private String configuredAuthServer;
	
	private String configuredIssuer;
	
	private final String rest_uri = "https://ec2-52-221-234-166.ap-southeast-1.compute.amazonaws.com:8443/octest-frontend-api";

	@Autowired
	private HttpServletRequest request;

	/**
	 * 
	 * @return
	 */
	private KeycloakSecurityContext getCurrentSecurityContext() {

		if (request.getUserPrincipal() != null) {
			KeycloakAuthenticationToken authenticated = (KeycloakAuthenticationToken) request.getUserPrincipal();
			KeycloakPrincipal<?> usr_principal = (KeycloakPrincipal<?>) authenticated.getPrincipal();

			return usr_principal.getKeycloakSecurityContext();

		} else {
			return null;
		}
	}

	/**
	 * Assign value to the model
	 * 
	 * @return null
	 */
	private KeyCloakUserInfo configModel(Model model) {

		KeyCloakUserInfo usr_info = new KeyCloakUserInfo(getCurrentSecurityContext());
		model.addAttribute("user", usr_info);

		return usr_info;
	}

	/**
	 * Assign value to the model
	 * 
	 * @return null
	 */
	private void configPageModel(Model model, String key, String result) {
		model.addAttribute(key, result);
	}

	@RequestMapping("/")
	public String home(Model model) {
		configModel(model);
		return "home";
	}
	
	@RequestMapping("/sys-support")
	public String displaySysSupport(Model model) {
		
		String METHOD_NM = "displaySysSupport()";
		String rest_dest = rest_uri + "/sys-support"; // URL to append with page that wish to access
		
		try {
			
			KeyCloakUserInfo usr_info = configModel(model);
			String[] retVal = checkTicketPermission(getCurrentSecurityContext(), "user-author-sys-support").split("\\|");
			
			RestTemplate restful = restTemplate();
			HttpHeaders headers = new HttpHeaders();
			//headers.add("Authorization", "Bearer " + usr_info.getAccessToken());
			headers.add("Authorization", "Bearer " + retVal[0]);
			
			HttpEntity<String> entity = new HttpEntity<>("body", headers);
			ResponseEntity<String> resp = restful.exchange(rest_dest, HttpMethod.GET, entity, String.class); 

			configPageModel(model, "page", resp.getBody());
			configPageModel(model, "token", usr_info.getAccessToken());

		} catch (Exception e) {
			System.err.println(METHOD_NM + " Exception: [" + e.getMessage() + "].");
			configPageModel(model, "error", e.getMessage());
		}

		return "sys-support";
	}

	@RequestMapping("/it-sec-admin")
	public String displayITSecAdmin(Model model) {
		
		String METHOD_NM = "displayITSecAdmin()";
		String rest_dest = rest_uri + "/it-sec-admin"; // URL to append with page that wish to access
		
		try {

			KeyCloakUserInfo usr_info = configModel(model);

			RestTemplate restful = restTemplate();
			HttpHeaders headers = new HttpHeaders();
			headers.add("Authorization", "Bearer " + usr_info.getAccessToken());
			
			HttpEntity<String> entity = new HttpEntity<>("body", headers);
			ResponseEntity<String> resp = restful.exchange(rest_dest, HttpMethod.GET, entity, String.class); 

			configPageModel(model, "page", resp.getBody());
			configPageModel(model, "token", usr_info.getAccessToken());
			
		} catch (Exception e) {
			System.err.println(METHOD_NM + " Exception: [" + e.getMessage() + "].");
			configPageModel(model, "error", e.getMessage());
		}
		
		return "it-sec-admin";
	}

	private RestTemplate restTemplate() throws Exception {

		SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(trustStore.getURL(), trustStorePassword.toCharArray()).build();
		SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
		HttpClient httpClient = HttpClients.custom().setSSLSocketFactory(socketFactory).build();
		HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);

		return new RestTemplate(factory);
	}
	
	private String checkTicketPermission(KeycloakSecurityContext sc, String targeted_aud) throws Exception {

		String METHOD_NM = "checkTicketPermission()";
		configuredIssuer = configuredAuthServer + "/realms/" + configuredRealm;

		RestTemplate restful = restTemplate();
		HttpHeaders headers = new HttpHeaders();
		HttpEntity<MultiValueMap<String, String>> entity;
		ResponseEntity<String> resp;
		JSONObject obj;
		
		//Requesting Permission Ticket from KeyCloak
		headers.add("Authorization", "Bearer " + sc.getTokenString());
		headers.add("Content-Type", "application/x-www-form-urlencoded");

		MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();
		map.add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
		map.add("audience", targeted_aud);

		entity = new HttpEntity<MultiValueMap<String, String>>(map, headers);
		resp = restful.exchange(configuredIssuer + "/protocol/openid-connect/token", HttpMethod.POST, entity, String.class);

		System.out.println(METHOD_NM + "Response from Key Cloak: [" + resp.getBody() + "].");
		
		// Forming JSON Object with response from key cloak
		obj = new JSONObject(resp.getBody());

		// Form JsonWebToken based on permission ticket (access token)
		JsonWebToken jwt = TokenVerifier.create(obj.get("access_token").toString(), JsonWebToken.class).getToken();
		
		/**
		 * Developer may verify permission ticket by using following options
		 * 1) Manual check for permission granted to users (based on resources)
		 * OR
		 * 2) Manual check for resources & roles granted to users
		 * This POC having 2 method of checking for developer references.
		 */
		// Method 1:
		Map<?,?> auth = (LinkedHashMap<?,?>)jwt.getOtherClaims().get("authorization");
		List<?> auth_permission = (List<?>) auth.get("permissions");

		for (int i = 0 ; i < auth_permission.size() ; i++) {
			System.out.println(METHOD_NM + "Count [" + (i+1) + "]-"+ auth_permission.get(i));
			//TODO teams can cross check with the resource value and its scopes to determine the access
		}

		// Method 2:
		Map<?,?> auth_resource = (LinkedHashMap<?,?>)jwt.getOtherClaims().get("resource_access");
		System.out.println(METHOD_NM + "Resource Access Class [" + auth_resource.keySet()+ "].");
		
		for (int i = 0 ; i < auth_resource.size() ; i++) {
			System.out.println(METHOD_NM + "Count [" + (i+1) + "]-"+ auth_resource.get(targeted_aud)); //TODO to be define based on the user configuration
			//TODO teams can cross check with the roles assigned to users to determine if it is accessible.
		}
		
		return obj.get("access_token").toString() + "|" + auth_permission.toString() + "|" + auth_resource.get(targeted_aud);
	}


}
