package org.epragati.security.vo;

import java.io.Serializable;

public class CaptchaValidationVO implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private boolean status;
	private String httpStatus;

	public boolean isResult() {
		return result;
	}

	public void setResult(boolean result) {
		this.result = result;
	}

	private boolean result;
	private String errors;
	private String fieldErrors;
	private String message;

	/**
	 * @return the status
	 */
	public boolean getStatus() {
		return status;
	}

	/**
	 * @param status the status to set
	 */
	public void setStatus(boolean status) {
		this.status = status;
	}

	/**
	 * @return the httpStatus
	 */
	public String getHttpStatus() {
		return httpStatus;
	}

	/**
	 * @param httpStatus the httpStatus to set
	 */
	public void setHttpStatus(String httpStatus) {
		this.httpStatus = httpStatus;
	}

	/**
	 * @return the result the errors
	 */
	public String getErrors() {
		return errors;
	}

	/**
	 * @param errors the errors to set
	 */
	public void setErrors(String errors) {
		this.errors = errors;
	}

	/**
	 * @return the fieldErrors
	 */
	public String getFieldErrors() {
		return fieldErrors;
	}

	/**
	 * @param fieldErrors the fieldErrors to set
	 */
	public void setFieldErrors(String fieldErrors) {
		this.fieldErrors = fieldErrors;
	}

	/**
	 * @return the message
	 */
	public String getMessage() {
		return message;
	}

	/**
	 * @param message the message to set
	 */
	public void setMessage(String message) {
		this.message = message;
	}

}
