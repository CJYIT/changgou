package com.changgou.token;

import ch.qos.logback.core.net.ssl.KeyStoreFactoryBean;
import com.alibaba.fastjson.JSON;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.net.ssl.KeyManagerFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;

/****
 * 令牌的创建和解析
 * @Author:cjy
 * @Description: com.changgou.token
 * @Date
 *****/
public class CreateJweTestDemo {
    /**
     * 创建令牌
     */
    @Test
    public void testCreateToken(){
        //加载证书
        ClassPathResource resource = new ClassPathResource("changgou68.jks");//读取类路径下的文件
        //读取证书
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(resource,"changgou68".toCharArray());//加载读取证书数据
        //获取证书中的一对密钥
        KeyPair keyPair = keyStoreKeyFactory.getKeyPair("changgou68","changgou68".toCharArray());
         //获取私钥->RSA算法   ctrl点击进去查看PrivateKey的源码，然后再ctrl+alt+b查看子接口的实现类
        //父接口转成子接口
//        PrivateKey privateKey = keyPair.getPrivate();//可以查看到PrivateKey的子接口，下面使用子接口RSAPrivateKey进行强转
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        //创建令牌需要私钥加盐
        HashMap<String, Object> playload = new HashMap<>();
        playload.put("nikename","tomcat");
        playload.put("adress","sz");
        playload.put("rile","admin,user");

        Jwt jwt = JwtHelper.encode(JSON.toJSONString(playload),new RsaSigner(privateKey));

        //获取令牌
        String token = jwt.getEncoded();
        System.out.println(token);

    }

    //解析令牌
    @Test
    public void testParseToken(){
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJyaWxlIjoiYWRtaW4sdXNlciIsIm5pa2VuYW1lIjoidG9tY2F0IiwiYWRyZXNzIjoic3oifQ.elMuqGvEKmJA3eWxGd0ijbscsg7cVC4U4_IkEjkYtInhnBu0J74Uidg5MEtOpiYoNonvd5eeC5IjHvZOr-BicS3nxvlo9eT_YjscDKLLYecIhZypYr2aOv_e6L-hbZTH_9mA_TOcX3fT2VyFbEtkqcHRih8CAaQu6Q2saNM_cqDPF8t9f4V2hjpKNxGpAhdohInhCGdkvr_1hxMgom0cgJG7tkDiH9Ffl1ZOlVakJ61TobcwXvJEMa4rHSbtY03KxDRWc5Z3OsuyS1KBRgQhDTbWivTBxdEmb_UQi1iEPlFcJIgxjajdaxQ8yH8l0vrVEB-lE2jmhb475JeOpPr2hw";
        String publickey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmQ/FGGv4B/w/j2Ic9sadEdE2epOKf7vDxxMOGzdzVk4eRMEPEFaYjzRj6fOOQgrKf7HOqIheMtiLdAO0sJdmGNG4g/a7aXa7ozA7cLfz4K3WMDQ6fFnXEp7e0PM9Tfny+Vzl2LRH6Q+Y19YVIH66bQRUmB2+LWYlD3UTN9Th65sti+oguMI/AQ3tydaSrpXDhsw7iJVQ6rkP654JiEwcudkR0SsStuoPj6TcMp0J20/vvA3kuIaNmve/IDd++lCbBXvsYf/vd1xY3lOE8dzqH9+aFA+qqYbrDihe+kCq1XgfcnLmPpydio0HthvnY/lt1cLBFDqDNx/SUAsjd00Z7QIDAQAB-----END PUBLIC KEY-----";
        //两个参数，密钥和签名
        Jwt jwt = JwtHelper.decodeAndVerify(token,
                new RsaVerifier(publickey)
        );
        String claims = jwt.getClaims();
        System.out.println(claims);
    }
}
