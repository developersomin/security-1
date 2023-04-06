package springsecurity.security1.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import springsecurity.security1.config.oauth.PrincipalOauth2UserService;



//@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
// @EnableGlobalMethodSecurity 어노테이션의 속성으로 securedEnabled 를 true
// @Secured(특정 권한만 접근이 가능하다는 것을 나타내는 Annotation) 어노테이션을,
// prePostEnabled를 true @PreAuthorize와 @PostAuthorize를 사용할 수 있음.
// 단순하게 특정 권한을 가진 사람이 아닌 다양한 조건이 들어가야 되는 경우


@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {


    private final PrincipalOauth2UserService principalOauth2UserService;

    //해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
    @Bean
    public BCryptPasswordEncoder encoderPwd() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                // .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN') or
                // hasRole('ROLE_USER')")
                // .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN') and
                // hasRole('ROLE_USER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/")
                .and()
                .logout()
                .logoutUrl("/logout")
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService);


        return http.build();


        //1.코드받기(인증) 2. 엑세스토큰(권한)
        //3. 사용자프로필 정보를 가져옴
        //4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 방법1
        //4-2. 회원가입시 구글에 가져온 정보 추가로 주소나 등급 등 으로 추가적인 장보로 회원가입 방법2



    }
}
