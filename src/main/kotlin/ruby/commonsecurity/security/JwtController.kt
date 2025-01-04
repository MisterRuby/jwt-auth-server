package ruby.commonsecurity.security

import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import ruby.commonsecurity.security.jwt.Jwk
import ruby.commonsecurity.security.jwt.JwtUtils

@RestController
class JwtController(
    private val jwtUtils: JwtUtils
) {

    @PostMapping("/jwt/update-keys")
    fun updateKey(@RequestBody jwk: Jwk): String {
        println("updateKey")

        // 인증서버로부터 받은 jwk
        jwtUtils.generatePublicKey(jwk)

        return "OK";
    }
}
