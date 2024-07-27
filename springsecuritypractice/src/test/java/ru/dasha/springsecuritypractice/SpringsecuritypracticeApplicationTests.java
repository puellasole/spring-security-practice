package ru.dasha.springsecuritypractice;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class SpringsecuritypracticeApplicationTests {
	
	@Autowired
	private MockMvc mockMvc;
	
	@Test
	@WithMockUser(username = "user", authorities = "developers:read")
	void test1() throws Exception{
		mockMvc.perform(delete("/api/v1/developers/1")).andExpect(status().isForbidden());
	}
	
	@Test
	@WithMockUser(username = "admin", authorities = "developers:write")
	void test2() throws Exception{
		mockMvc.perform(delete("/api/v1/developers/1")).andExpect(status().isOk());
	}
	
	@Test
	void test3() throws Exception{
		mockMvc.perform(delete("/api/v1/developers/3")
                .with(user("admin").authorities(Role.ADMIN.getAuthorities()))) 
                .andExpect(status().isOk());
	}
	/*
	@Test
	void test4() throws Exception{
		mockMvc.perform(get("/api/v1/developers")
                .with(user("user")))
                .andExpect(status().isOk());
	}
	
	@Test
	void testAll() throws Exception{
		mockMvc.perform(delete("/api/v1/developers/2")
                .with(user("user")))
                .andExpect(status().isForbidden());
	}*/
}
