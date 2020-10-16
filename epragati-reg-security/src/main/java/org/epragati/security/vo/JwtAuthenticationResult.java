package org.epragati.security.vo;

import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.epragati.master.dto.RolesDTO;

public class JwtAuthenticationResult implements Serializable {

	private static final long serialVersionUID = -150474087941559518L;
	
	private String id;
	private String firstname;
	private String lastname;
	private String primaryRole;
	private List<String> additionalRoles;
	private String token;
	private String officeCode;
	private boolean isPasswordResetRequired;
	private final String parentUserId;
	private final boolean isParent;
	private LocalDate validTo;
	private String lastLoginTime;
	
	public JwtAuthenticationResult(String id, String firstname, String lastname, RolesDTO primaryRole,
			List<RolesDTO> additionalRoles,String token, String officeCode, String parentUserId,boolean isParent, boolean isPasswordResetRequired,LocalDate validTo,String lastLoginTime) {
		this.id = id;
		this.firstname = firstname;
		this.lastname = lastname;
		this.primaryRole = primaryRole.getName();
		this.additionalRoles = additionalRoles!=null?additionalRoles.stream().map(r->r.getName()).collect(Collectors.toList()):Collections.emptyList();
		this.token=token;
		this.officeCode=officeCode;
		this.parentUserId=parentUserId;
		this.isParent=isParent;
		this.isPasswordResetRequired = isPasswordResetRequired;
		this.validTo = validTo;
		this.lastLoginTime = lastLoginTime;
		
	}
	
	/*
	 * public JwtAuthenticationResult(String id, String firstname, String lastname,
	 * String primaryRole, List<String> additionalRoles, String token, String
	 * officeCode, boolean isPasswordResetRequired, String parentUserId, boolean
	 * isParent, LocalDate validTo, LocalDateTime lastLoginTime) { super(); this.id
	 * = id; this.firstname = firstname; this.lastname = lastname; this.primaryRole
	 * = primaryRole; this.additionalRoles = additionalRoles; this.token = token;
	 * this.officeCode = officeCode; this.isPasswordResetRequired =
	 * isPasswordResetRequired; this.parentUserId = parentUserId; this.isParent =
	 * isParent; this.validTo = validTo; this.lastLoginTime = lastLoginTime; }
	 */
	public String getId() {
		return id;
	}
	public String getFirstname() {
		return firstname;
	}
	public String getLastname() {
		return lastname;
	}
	public String getPrimaryRole() {
		return primaryRole;
	}
	public List<String> getAdditionalRoles() {
		return additionalRoles;
	}
	public static long getSerialversionuid() {
		return serialVersionUID;
	}
	public String getToken() {
		return token;
	}
	public String getOfficeCode() {
		return officeCode;
	}
	/**
	 * @return the parentUserId
	 */
	public String getParentUserId() {
		return parentUserId;
	}
	/**
	 * @return the isParent
	 */
	public boolean isParent() {
		return isParent;
	}
	
	public boolean isPasswordResetRequired() {
		return isPasswordResetRequired;
	}
	public void setPasswordResetRequired(boolean isPasswordResetRequired) {
		this.isPasswordResetRequired = isPasswordResetRequired;
	}
	public LocalDate getValidTo() {
		return validTo;
	}
	public void setValidTo(LocalDate validTo) {
		this.validTo = validTo;
	}
	public String getLastLoginTime() {
		return lastLoginTime;
	}

	public void setLastLoginTime(String lastLoginTime) {
		this.lastLoginTime = lastLoginTime;
	}

	public void setId(String id) {
		this.id = id;
	}
	public void setFirstname(String firstname) {
		this.firstname = firstname;
	}
	public void setLastname(String lastname) {
		this.lastname = lastname;
	}
	public void setPrimaryRole(String primaryRole) {
		this.primaryRole = primaryRole;
	}
	public void setAdditionalRoles(List<String> additionalRoles) {
		this.additionalRoles = additionalRoles;
	}
	public void setToken(String token) {
		this.token = token;
	}
	public void setOfficeCode(String officeCode) {
		this.officeCode = officeCode;
	}
	
	
}
