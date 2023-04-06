package springsecurity.security1.config.auth;


import lombok.Data;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import springsecurity.security1.domain.User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

//시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
//로그인을 진행이 완료가 되면 session에 만들어줍니다.
//시큐리티 세션 안에 Authentication 인증 객체가 저장되는데
//인증객체 안에 UserDetails(일반로그인)나 OAuth2User(OAuth 로그인)가 들어갈수 있다.
//PrincipalDetails implements UserDetails, OAuth2User 두개를 묶는다.
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user;
    private Map<String,Object> attributes;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() { //계정의 만료 여부 리턴	true ( 만료 안됨 )
        return true;
    }

    @Override
    public boolean isAccountNonLocked() { //계정의 잠김 여부 리턴	true ( 잠기지 않음 )
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() { //비밀번호 만료 여부 리턴	true ( 만료 안됨 )
        return true;
    }

    @Override
    public boolean isEnabled() { //계정의 활성화 여부 리턴	true ( 활성화 됨 )
        return true;
    }


    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return null;
    }
}

