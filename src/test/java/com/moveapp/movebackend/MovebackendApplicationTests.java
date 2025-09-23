// MoveAppIntegrationTest.java
package com.moveapp.movebackend;
//
//import com.fasterxml.jackson.databind.ObjectMapper;
//import com.moveapp.movebackend.model.dto.AuthenticationDto.*;
//import com.moveapp.movebackend.model.dto.OtpDto.SendOtpRequest;
//import com.moveapp.movebackend.model.dto.OTPdto.*;
//import com.moveapp.movebackend.model.dto.LocationDto.*;
//import com.moveapp.movebackend.repository.OTPRepository;
//import com.moveapp.movebackend.repository.UserRepository;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.http.MediaType;
//import org.springframework.test.context.ActiveProfiles;
//import org.springframework.test.web.servlet.MockMvc;
//import org.springframework.test.web.servlet.setup.MockMvcBuilders;
//import org.springframework.transaction.annotation.Transactional;
//import org.springframework.web.context.WebApplicationContext;
//
//import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
//import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
//
@SpringBootTest
//@AutoConfigureWebMvc
//@ActiveProfiles("test")
//@Transactional
public class MovebackendApplicationTests {
//
//	@Autowired
//	private WebApplicationContext context;
//
//	@Autowired
//	private ObjectMapper objectMapper;
//
//	@Autowired
//	private UserRepository userRepository;
//
//	@Autowired
//	private OTPRepository otpRepository;
//
//	private MockMvc mockMvc;
//
//	@BeforeEach
//	void setUp() {
//		mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
//	}
//
//	@Test
//	void testAuthControllerEndpoints() throws Exception {
//		// Test auth controller basic endpoint
//		mockMvc.perform(get("/api/auth/test"))
//				.andExpect(status().isOk())
//				.andExpect(content().string("Auth controller is working!"));
//
//		// Test signup OTP request
//		SendOtpRequest otpRequest = SendOtpRequest.builder()
//				.email("newuser@example.com")
//				.type("SIGNUP_VERIFICATION")
//				.build();
//
//		mockMvc.perform(post("/api/auth/send-signup-otp")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(otpRequest)))
//				.andExpect(status().isOk())
//				.andExpect(jsonPath("$.success").value(true))
//				.andExpect(jsonPath("$.message").value("OTP sent successfully to your email"));
//
//		// Test signup with invalid email (should fail validation)
//		SendOtpRequest invalidOtpRequest = SendOtpRequest.builder()
//				.email("invalid-email")
//				.type("SIGNUP_VERIFICATION")
//				.build();
//
//		mockMvc.perform(post("/api/auth/send-signup-otp")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(invalidOtpRequest)))
//				.andExpect(status().isBadRequest());
//
//		// Test regular signup
//		SignupRequest signupRequest = SignupRequest.builder()
//				.name("Test User")
//				.email("testuser@example.com")
//				.password("password123")
//				.build();
//
//		mockMvc.perform(post("/api/auth/signup")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(signupRequest)))
//				.andExpected(status().isCreated())
//				.andExpect(jsonPath("$.accessToken").exists())
//				.andExpect(jsonPath("$.user.email").value("testuser@example.com"));
//
//		// Test signin with created user
//		AuthRequest authRequest = AuthRequest.builder()
//				.email("testuser@example.com")
//				.password("password123")
//				.build();
//
//		mockMvc.perform(post("/api/auth/signin")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(authRequest)))
//				.andExpect(status().isOk())
//				.andExpect(jsonPath("$.accessToken").exists())
//				.andExpect(jsonPath("$.user.email").value("testuser@example.com"));
//
//		// Test signin with wrong password
//		AuthRequest wrongAuthRequest = AuthRequest.builder()
//				.email("testuser@example.com")
//				.password("wrongpassword")
//				.build();
//
//		mockMvc.perform(post("/api/auth/signin")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(wrongAuthRequest)))
//				.andExpect(status().isUnauthorized());
//	}
//
//	@Test
//	void testOTPControllerEndpoints() throws Exception {
//		// Test OTP send endpoint
//		SendOtpRequest otpRequest = SendOtpRequest.builder()
//				.email("test@example.com")
//				.type("SIGNUP_VERIFICATION")
//				.build();
//
//		mockMvc.perform(post("/api/otp/send")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(otpRequest)))
//				.andExpect(status().isOk())
//				.andExpect(jsonPath("$.success").value(true));
//
//		// Test OTP verify with wrong code
//		VerifyOtpRequest verifyRequest = VerifyOtpRequest.builder()
//				.email("test@example.com")
//				.otp("000000")
//				.type("SIGNUP_VERIFICATION")
//				.build();
//
//		mockMvc.perform(post("/api/otp/verify")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(verifyRequest)))
//				.andExpect(status().isOk())
//				.andExpect(jsonPath("$.success").value(false))
//				.andExpect(jsonPath("$.message").value("Invalid OTP code"));
//
//		// Test invalid OTP type
//		SendOtpRequest invalidTypeRequest = SendOtpRequest.builder()
//				.email("test@example.com")
//				.type("INVALID_TYPE")
//				.build();
//
//		mockMvc.perform(post("/api/otp/send")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(invalidTypeRequest)))
//				.andExpect(status().isBadRequest());
//	}
//
//	@Test
//	void testLocationControllerEndpoints() throws Exception {
//		// Test location search
//		mockMvc.perform(get("/api/locations/search")
//						.param("query", "restaurant")
//						.param("page", "0")
//						.param("size", "10"))
//				.andExpect(status().isOk())
//				.andExpected(jsonPath("$.results").isArray())
//				.andExpect(jsonPath("$.query").value("restaurant"))
//				.andExpect(jsonPath("$.page").value(0))
//				.andExpect(jsonPath("$.size").value(10));
//
//		// Test popular locations
//		mockMvc.perform(get("/api/locations/popular"))
//				.andExpect(status().isOk())
//				.andExpect(jsonPath("$").isArray());
//
//		// Test locations by category
//		mockMvc.perform(get("/api/locations/category/RESTAURANT"))
//				.andExpect(status().isOk())
//				.andExpect(jsonPath("$").isArray());
//
//		// Test nearby locations
//		mockMvc.perform(get("/api/locations/nearby")
//						.param("latitude", "40.7128")
//						.param("longitude", "-74.0060")
//						.param("radius", "5.0"))
//				.andExpect(status().isOk())
//				.andExpect(jsonPath("$").isArray());
//
//		// Test reverse geocoding
//		mockMvc.perform(get("/api/locations/reverse")
//						.param("latitude", "40.7128")
//						.param("longitude", "-74.0060"))
//				.andExpect(status().isOk())
//				.andExpect(jsonPath("$.latitude").value(40.7128))
//				.andExpect(jsonPath("$.longitude").value(-74.0060));
//
//		// Test invalid coordinates
//		mockMvc.perform(get("/api/locations/nearby")
//						.param("latitude", "200")  // Invalid latitude
//						.param("longitude", "-74.0060")
//						.param("radius", "5.0"))
//				.andExpected(status().isBadRequest());
//	}
//
//	@Test
//	void testLocationControllerAuthenticationRequired() throws Exception {
//		// Test live location endpoints require authentication
//		LiveLocationUpdateRequest locationUpdate = LiveLocationUpdateRequest.builder()
//				.latitude(40.7128)
//				.longitude(-74.0060)
//				.accuracy(10.0)
//				.build();
//
//		mockMvc.perform(post("/api/locations/live/update")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(locationUpdate)))
//				.andExpected(status().isUnauthorized());
//
//		mockMvc.perform(get("/api/locations/live/current"))
//				.andExpect(status().isUnauthorized());
//
//		LocationShareRequest shareRequest = LocationShareRequest.builder()
//				.enabled(true)
//				.build();
//
//		mockMvc.perform(post("/api/locations/live/share")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(shareRequest)))
//				.andExpect(status().isUnauthorized());
//
//		mockMvc.perform(post("/api/locations/live/stop"))
//				.andExpect(status().isUnauthorized());
//	}
//
//	@Test
//	void testValidationErrors() throws Exception {
//		// Test empty email validation
//		SendOtpRequest emptyEmailRequest = SendOtpRequest.builder()
//				.email("")
//				.type("SIGNUP_VERIFICATION")
//				.build();
//
//		mockMvc.perform(post("/api/otp/send")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(emptyEmailRequest)))
//				.andExpect(status().isBadRequest());
//
//		// Test signup with short password
//		SignupRequest shortPasswordRequest = SignupRequest.builder()
//				.name("Test User")
//				.email("test@example.com")
//				.password("123")  // Too short
//				.build();
//
//		mockMvc.perform(post("/api/auth/signup")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(shortPasswordRequest)))
//				.andExpected(status().isBadRequest());
//
//		// Test location search without query
//		mockMvc.perform(get("/api/locations/search"))
//				.andExpect(status().isBadRequest());
//	}
//
//	@Test
//	void testPasswordReset() throws Exception {
//		// First create a user
//		SignupRequest signupRequest = SignupRequest.builder()
//				.name("Test User")
//				.email("resettest@example.com")
//				.password("oldpassword")
//				.build();
//
//		mockMvc.perform(post("/api/auth/signup")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(signupRequest)))
//				.andExpected(status().isCreated());
//
//		// Request password reset OTP
//		SendOtpRequest resetOtpRequest = SendOtpRequest.builder()
//				.email("resettest@example.com")
//				.type("PASSWORD_RESET")
//				.build();
//
//		mockMvc.perform(post("/api/auth/password/forgot")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(resetOtpRequest)))
//				.andExpected(status().isOk())
//				.andExpect(jsonPath("$.success").value(true));
//
//		// Test password reset with invalid OTP
//		ResetPasswordRequest resetRequest = ResetPasswordRequest.builder()
//				.email("resettest@example.com")
//				.otp("000000")
//				.newPassword("newpassword")
//				.build();
//
//		mockMvc.perform(post("/api/auth/password/reset")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(resetRequest)))
//				.andExpect(status().isBadRequest());
//	}
//
//	@Test
//	void testCompleteSignupWithOTPFlow() throws Exception {
//		String email = "otpuser@example.com";
//
//		// 1. Request signup OTP
//		SendOtpRequest otpRequest = SendOtpRequest.builder()
//				.email(email)
//				.type("SIGNUP_VERIFICATION")
//				.build();
//
//		mockMvc.perform(post("/api/auth/send-signup-otp")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(otpRequest)))
//				.andExpect(status().isOk())
//				.andExpected(jsonPath("$.success").value(true));
//
//		// 2. Try to signup with wrong OTP (should fail)
//		SignupWithOtpRequest wrongOtpSignup = SignupWithOtpRequest.builder()
//				.name("OTP User")
//				.email(email)
//				.password("password123")
//				.otp("000000")
//				.build();
//
//		mockMvc.perform(post("/api/auth/signup/with-otp")
//						.contentType(MediaType.APPLICATION_JSON)
//						.content(objectMapper.writeValueAsString(wrongOtpSignup)))
//				.andExpect(status().isBadRequest());
//
//		// Note: For a complete test, you'd need to retrieve the actual OTP from the database
//		// and use it in the signup request, but that requires additional setup
//	}
//
//	@Test
//	void testConcurrentOTPRequests() throws Exception {
//		String email = "concurrent@example.com";
//
//		SendOtpRequest otpRequest = SendOtpRequest.builder()
//				.email(email)
//				.type("SIGNUP_VERIFICATION")
//				.build();
//
//		// Send multiple OTP requests rapidly
//		for (int i = 0; i < 5; i++) {
//			mockMvc.perform(post("/api/auth/send-signup-otp")
//							.contentType(MediaType.APPLICATION_JSON)
//							.content(objectMapper.writeValueAsString(otpRequest)))
//					.andExpected(status().isOk());
//		}
//
//		// The service should handle rate limiting and return appropriate responses
//	}
}