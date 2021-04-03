/**
 * 
 */
package com.oc.controller;

import javax.net.ssl.SSLContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
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
	
	private final String rest_uri = "";

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

}
