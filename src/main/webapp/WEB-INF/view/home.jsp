<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Integration between TYK and KeyCloak (POC)</title>
</head>
<body>
	<h1>Proof of Concept (POC) for integration between TYK and KeyCloak</h1>
	<h2>Home</h2>

	<c:if test="${not empty fn:trim(user.name)}">
		<h3>Current User: ${user.name}</h3>
		<br>
		<br>
		<a href="${pageContext.request.contextPath}/sys-support">System Support Function</a>
		<br>
		<br>
		<a href="${pageContext.request.contextPath}/it-sec-admin">IT Security Admin Function</a>
		<br>
		<br>
		<form:form method="POST" id="form_logout"
			action="${pageContext.request.contextPath}/sso/logout">
			<input id="logout" type="submit" value="Logout" />
		</form:form>
	</c:if>

	<c:if test="${empty fn:trim(user.name)}">
		<form:form method="POST" id="form_login"
			action="${pageContext.request.contextPath}/sso/login">
			<input id="login" type="submit" value="Login" />
		</form:form>
	</c:if>

</body>
</html>