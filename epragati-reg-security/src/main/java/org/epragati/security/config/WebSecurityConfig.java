package org.epragati.security.config;

import org.epragati.security.eumns.UserType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@ComponentScan(basePackages = { "org.epragati.*" })
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private JwtAuthenticationEntryPoint unauthorizedHandler;

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	public void configureAuthentication(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
		authenticationManagerBuilder.userDetailsService(this.userDetailsService).passwordEncoder(passwordEncoder());
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public JwtAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
		return new JwtAuthenticationTokenFilter();
	}

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
				// we don't need CSRF because our token is invulnerable
		.csrf().disable()

				.exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()

				// don't create session
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()

				.authorizeRequests().antMatchers(HttpMethod.OPTIONS, "/**").permitAll().antMatchers("/cardPrint/**")
				.hasAuthority(UserType.ROLE_CARDPRINTING.getLabel())
//                .antMatchers(
//    				"/admin/**"
//    			).hasAnyAuthority(UserType.ROLE_CCO.getLabel(),UserType.ROLE_AO.getLabel(),UserType.ROLE_MVI.getLabel(),UserType.ROLE_RTO.getLabel())

				//.antMatchers("/admin/saveObjectionDetails").hasAnyAuthority(UserType.ROLE_CCO.getLabel())
				.antMatchers("/admin/saveObjectionDetails").permitAll()
				/*
				 * .antMatchers( "/admin/saveRevocationDetails"
				 * ).hasAnyAuthority(UserType.ROLE_RTO.getLabel())
				 */

				// allow anonymous resource requests
				.antMatchers(HttpMethod.GET, "/", "/*.html", "/favicon.ico", "/**/*.html", "/**/*.css", "/**/*.js",
						"/**/*.png", "/**/*.jpg", "/**/*.woff", "/**/*.eot", "/**/*.woff2", "/**/*.ttf", "/fonts/*.*",
						"/v2/api-docs/*", "/api/**")
				.permitAll().antMatchers(HttpMethod.OPTIONS, "/**").permitAll().antMatchers("/auth/**").permitAll()
				.antMatchers("/commonAuth/**").permitAll().antMatchers("/authExternal/**").permitAll()
				.antMatchers("/images/**").permitAll().antMatchers("/getEncPwd/**").permitAll()
				.antMatchers("/payment/**").permitAll().antMatchers("/posttrhsrp").permitAll()
				.antMatchers("/postprhsrp").permitAll().antMatchers("/api/**").permitAll()
				/*
				 * .antMatchers("/api-docs/**").permitAll()
				 * .antMatchers("/v2/api-docs/**").permitAll()
				 */
			
				.antMatchers("/getSpecialNumDetails").permitAll().antMatchers("/generateCaptcha/**").permitAll()
				.antMatchers("/devopsTest/**").permitAll().antMatchers("/elasticSearchTest").permitAll()
				.antMatchers("/master/**").permitAll().antMatchers("/getRegistrationDetails").permitAll()
				.antMatchers("/citizenServices/**").permitAll().antMatchers("/cfstPayment/**").permitAll()
				.antMatchers("/getTrDetails").permitAll().antMatchers("/financier/fetchFinancerApplicationSeries")
				.permitAll().antMatchers("/financier/financierSave").permitAll()
				.antMatchers("/financier/getFinancierDetailsByFinAppNo").permitAll()
				.antMatchers("/financier/getListOfRejectedEnclosureDetails").permitAll()
				.antMatchers("/financier/getListOfRejectedEnclosureDetails").permitAll()
				.antMatchers("/financier/getSupportedEnclosuresForService").permitAll()
				.antMatchers("/financier/reUpdateFinancierDetailsByFinAppNo").permitAll()
				.antMatchers("/financier/getRCDetailsReport").permitAll()
				/* .antMatchers("/bodyBuilder/saveAlterationDetails").permitAll() */
				.antMatchers("/getSpecialNumReport").permitAll().antMatchers("/getTranspPrData").permitAll()
				.antMatchers("/cfst/saveElsDetails").permitAll().antMatchers("/getfinancesactionletter").permitAll()
				.antMatchers("/getSecondVehicleData").permitAll().antMatchers("/getTrPrData").permitAll()
				.antMatchers("/getpermittvp").permitAll().antMatchers("/getpermitpc").permitAll()
				.antMatchers("/getpermitsbp").permitAll().antMatchers("/dealer/getSupportedEnclosuresForService")
				.permitAll()
				/* .antMatchers("/admin/saveMviActions/**").permitAll() */
				// .antMatchers("/admin//getSuspensionSections").permitAll()
				.antMatchers("/verifyPay/**").permitAll().antMatchers("/getNocTemplDetails").permitAll()
				/* .antMatchers("/admin/doActionForFC").permitAll() */
				.antMatchers("/cfmsProcessResponse").permitAll().antMatchers("/getFCDetails").permitAll()
				.antMatchers("/mobileServices/**").permitAll().antMatchers("/fetchhsrpdetails**").permitAll()
				.antMatchers("/getCfstTaxDetails/saveCfstTaxDetails**").permitAll()
				/*
				 * .antMatchers("/financier/freshRcFinanceProcess").permitAll()
				 * .antMatchers("/admin/freshRcFinanceProcessAtMVI").permitAll()
				 */

				.antMatchers("/motordrivingschool/getVehicleDetails").permitAll()
				.antMatchers("/motordrivingschool/getRepresentativeDetails").permitAll()
				.antMatchers("/motordrivingschool/getDriverDetails").permitAll()
				.antMatchers("/motordrivingschool/motorDrivingSchoolSave").permitAll()
				.antMatchers("/motordrivingschool/getSupportedEnclosuresForMds").permitAll()
				.antMatchers("/motordrivingschool/checkStatus").permitAll()
				.antMatchers("/motordrivingschool/getMVIDetailsBasedonOfficeName").permitAll()
				.antMatchers("/motordrivingschool/userIdGeneration").permitAll()
				.antMatchers("/motordrivingschool/getAllOfficesOfDistrict").permitAll()
				.antMatchers("/motordrivingschool/getRTAUsers").permitAll()

				.antMatchers("/generatePdfForAadtr").permitAll()


				.antMatchers("/eibtRegistration/eibtSignUp").permitAll()
				/* .antMatchers("/eibtRegistration/saveEnclosuresForEibt").permitAll() */
				.antMatchers("/schedulers/test/handleTRExpiredRecods").permitAll()
				.antMatchers("/getUserPasswordDetails").permitAll().antMatchers("/userPasswordResetDetails").permitAll()
				.antMatchers("/uid_status/**").permitAll().antMatchers("/chkAdhrWithUser/**").permitAll()
				// .antMatchers("/payment/getPaymentGateways").permitAll()
				.antMatchers("/payment/getPaymentDetailsForOtherServices").permitAll()
				.antMatchers("/dealer/dealerDetailsSave**").permitAll()
				.antMatchers("/stageCarriage/**").permitAll()
				.antMatchers("/dealer/doDealerRePay**").permitAll()
				.antMatchers("/dealer/getListOfDealers**").permitAll()
				.antMatchers("/dealer/getListOfMakers**").permitAll()
				.antMatchers("/dealer/getListOfVariations**").permitAll()
				.antMatchers("/getProcessPendingTransactionDetails").permitAll()
				.antMatchers("/payment/getPaymentDetailsForOtherServices**").permitAll()
				.antMatchers("/payment/getPaymentGateways**").permitAll()
				.antMatchers("/admin/getDealerDetails**").permitAll()
				.antMatchers("/dealer/searchForDealerRegistration**").permitAll()
				.antMatchers("/admin/getDetailsForFinancialAssiatance**").permitAll()
				.antMatchers("/admin/saveDataforFinancialAssiatance**").permitAll()
				.antMatchers("/admin/getMdoFinancialAssistance**").permitAll()
				.antMatchers("/vcr/getVahanDataForApp").permitAll()
				.antMatchers("/vcr/generateVcr").permitAll()
				.antMatchers("/vcr/saveSpeedGunData").permitAll()
				.antMatchers("/getUserIdFromToken").permitAll()
			    .anyRequest().authenticated();
		/*
		 * .antMatchers("/paymentReports/paymentDetailsExcel").permitAll()
		 * .antMatchers("/paymentReports/getPaymentsReport").permitAll()
		 */
		// .antMatchers("api/getVahanVehicleDetails**").permitAll()
		// .antMatchers("payment/getCfmsEodReport").permitAll()

		// Custom JWT based security filter getFinancierDetailsByFinAppNo
		httpSecurity.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);

		// disable page caching
		httpSecurity.headers().disable();
	}
}