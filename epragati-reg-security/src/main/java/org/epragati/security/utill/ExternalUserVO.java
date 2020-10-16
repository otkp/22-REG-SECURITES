package org.epragati.security.utill;

public class ExternalUserVO {


	private String userId;
	private String name;
	/*private String gender;*/
	private String mobile;
	private String email;
	/*private String accountName;
	private String accountToken;*/

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	/*public String getGender() {
		return gender;
	}

	public void setGender(String gender) {
		this.gender = gender;
	}*/

	public String getMobile() {
		return mobile;
	}

	public void setMobile(String mobile) {
		this.mobile = mobile;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

/*	public String getAccountName() {
		return accountName;
	}

	public void setAccountName(String accountName) {
		this.accountName = accountName;
	}

	public String getAccountToken() {
		return accountToken;
	}

	public void setAccountToken(String accountToken) {
		this.accountToken = accountToken;
	}*/

}

