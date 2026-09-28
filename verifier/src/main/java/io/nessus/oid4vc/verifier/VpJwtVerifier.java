package io.nessus.oid4vc.verifier;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

public final class VpJwtVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(VpJwtVerifier.class);

    @SuppressWarnings("unchecked")
    public String verifyAndExtract(SignedJWT vpJwt) throws VcVerificationException {
        try {
            var header = vpJwt.getHeader();
            var jwk = header.getJWK();
            if (jwk == null) {
                throw new VcVerificationException("VP JWT has no 'jwk' header");
            }
            if (!(jwk instanceof ECKey ecKey)) {
                throw new VcVerificationException("VP JWT holder key is not EC: " + jwk.getKeyType());
            }

            if (!vpJwt.verify(new ECDSAVerifier(ecKey.toPublicJWK()))) {
                throw new VcVerificationException("VP JWT holder signature verification failed");
            }

            var claims = vpJwt.getJWTClaimsSet();
            var vpClaim = claims.getClaim("vp");
            if (!(vpClaim instanceof Map<?,?> vp)) {
                throw new VcVerificationException("VP JWT has no 'vp' claim");
            }
            var vcs = (List<String>) vp.get("verifiableCredential");
            if (vcs == null || vcs.isEmpty()) {
                throw new VcVerificationException("VP JWT contains no verifiable credentials");
            }

            LOG.debug("VP JWT holder signature verified, extracted {} VC(s)", vcs.size());
            return vcs.getFirst();
        } catch (VcVerificationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new VcVerificationException("VP JWT verification error: " + ex.getMessage(), ex);
        }
    }
}
