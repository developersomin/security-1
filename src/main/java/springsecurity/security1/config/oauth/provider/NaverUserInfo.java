package springsecurity.security1.config.oauth.provider;

import java.util.Map;

public class NaverUserInfo implements OAuth2UserInfo {

    private Map<String,Object> attributes;//oauth2User.getAttributes()
    private Map<String,Object> attributesResponse;

    public NaverUserInfo(Map<String, Object> attributes) {

        this.attributes = attributes;
        this.attributesResponse = (Map<String,Object> )attributes.get("response");
    }

    @Override
    public String getProviderId() {
        return  attributesResponse.get("id").toString();
    }

    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getEmail() {
        return  attributesResponse.get("email").toString();
    }

    @Override
    public String getName() {
        return attributesResponse.get("name").toString();
    }
}
