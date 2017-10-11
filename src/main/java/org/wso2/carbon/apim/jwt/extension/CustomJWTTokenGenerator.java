package org.wso2.carbon.apim.jwt.extension;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.apimgt.keymgt.service.TokenValidationContext;
import org.wso2.carbon.apimgt.keymgt.token.JWTGenerator;

import java.util.HashMap;
import java.util.Map;

public class CustomJWTTokenGenerator extends JWTGenerator {

    public Map<String, String> populateStandardClaims(TokenValidationContext validationContext)
            throws APIManagementException {
        Map claims = super.populateStandardClaims(validationContext);

        String dialect = getDialectURI();
        if (claims.get(dialect + "/enduser") != null) {
            String enduser = (String) claims.get(dialect + "/enduser");
            if (enduser.endsWith("@carbon.super")) {
                enduser = enduser.replace("@carbon.super", "");
                claims.put(dialect + "/enduser", enduser);
            }
        }
        return claims;
    }

    public Map populateCustomClaims(APIKeyValidationInfoDTO keyValidationInfoDTO, String apiContext, String version, String accessToken)
            throws APIManagementException {
        Map map = new HashMap();
        map.put("current_timestamp", String.valueOf(System.currentTimeMillis()));
        map.put("message", "Custom claim value");
        return map;
    }
}
