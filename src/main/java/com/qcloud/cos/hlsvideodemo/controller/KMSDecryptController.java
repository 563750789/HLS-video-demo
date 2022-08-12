package com.qcloud.cos.hlsvideodemo.controller;

import com.tencentcloudapi.common.Credential;
import com.tencentcloudapi.common.exception.TencentCloudSDKException;
import com.tencentcloudapi.common.profile.ClientProfile;
import com.tencentcloudapi.common.profile.HttpProfile;
import com.tencentcloudapi.kms.v20190118.KmsClient;
import com.tencentcloudapi.kms.v20190118.models.DecryptRequest;
import com.tencentcloudapi.kms.v20190118.models.DecryptResponse;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

/**
 * @author markjrzhang
 * @date 2022/7/22 15:37
 */
@RestController
@CrossOrigin("*")
public class KMSDecryptController {

    @RequestMapping("decrypt")
    public void decrypt(@RequestParam("Ciphertext") String ciphertext,@RequestParam("KMSRegion") String region, HttpServletResponse response) {
        try {
            // 实例化一个认证对象，入参需要传入腾讯云账户secretId，secretKey,此处还需注意密钥对的保密
            // 密钥可前往https://console.cloud.tencent.com/cam/capi网站进行获取
            Credential cred = new Credential("", "");
            // 实例化http
            HttpProfile httpProfile = new HttpProfile();
            httpProfile.setEndpoint("kms.tencentcloudapi.com");
            // 实例化一个client选项，可选的，没有特殊需求可以跳过
            ClientProfile clientProfile = new ClientProfile();
            clientProfile.setHttpProfile(httpProfile);
            // 实例化要请求产品的client对象,clientProfile是可选的
            KmsClient client = new KmsClient(cred, region, clientProfile);
            // 实例化一个请求对象,每个接口都会对应一个request对象
            DecryptRequest req = new DecryptRequest();
            //写入待解密数据
            req.setCiphertextBlob(ciphertext);
            // 返回的resp是一个DecryptResponse的实例，与请求对象对应
            DecryptResponse resp = client.Decrypt(req);
            String plaintext = resp.getPlaintext();
            //对秘钥进行base64解密
            byte[] decode = Base64.getDecoder().decode(plaintext);
            //返回流
            ServletOutputStream outputStream = response.getOutputStream();
            outputStream.write(decode);
            outputStream.close();
        } catch (TencentCloudSDKException | IOException e) {
            System.out.println(e.toString());
        }
    }
}
