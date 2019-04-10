# 前言

后端接口开发中，涉及到用户私密信息（用户名、密码）等，我们不能传输明文，必须使用加密方式传输。这次政府项目中，安全测试组提出了明文传输漏洞，抽空研究了下Java加解密相关知识，记录下。

# 散列函数

Java提供了一个名为`MessageDigest`的类，它属于`java.security`包。 此类支持诸如`SHA-1`，`SHA 256`，`MD5`之类的算法，以将任意长度的消息转换为信息摘要。

散列函数返回的值称为信息摘要或简称散列值。 下图说明了散列函数。

![](https://i.loli.net/2019/04/10/5cade05f6faf5.png)

要使用散列函数加密数据，我们通常按照以下步骤执行：

## 创建MessageDigest对象

```java
MessageDigest md = MessageDigest.getInstance("MD5");
```

> `MessageDigest`提供了`getInstance`静态方法来获得`MessageDigest`实例，支持的类型可参考[Wiki-SHA家族](https://zh.wikipedia.org/wiki/SHA%E5%AE%B6%E6%97%8F)

## 将数据传递给创建的MessageDigest对象

```java
md.update("gcdd1993".getBytes());
```

## 生成消息摘要

```java
byte[] digest = md.digest();
```

## 通常我们会将其转换为Hex字符串

```java
StringBuffer hexString = new StringBuffer();

for (byte aDigest : digest) {
    hexString.append(Integer.toHexString(0xFF & aDigest));
}
System.out.println("Hex format : " + hexString.toString());
```

# 消息认证码

> MAC(消息认证码)算法是一种对称密钥加密技术，用于提供消息认证。要建立MAC过程，发送方和接收方共享对称密钥K。

实质上，MAC是在基础消息上生成的加密校验和，它与消息一起发送以确保消息验证。

使用MAC进行身份验证的过程如下图所示

![](https://i.loli.net/2019/04/10/5cade5aaeaede.png)

在Java中，`javax.crypto`包的Mac类提供了消息认证代码的功能。按照以下步骤使用此类创建消息身份验证代码。

## 创建KeyGenerator对象

```java
KeyGenerator keyGen = KeyGenerator.getInstance("DES");
```

> `KeyGenerator`支持以下类型：
>
> - AES (128)
> - DES (56)
> - DESede (168)
> - HmacSHA1
> - HmacSHA256

## 创建SecureRandom对象

```java
SecureRandom secureRandom = new SecureRandom();
```

## 初始化KeyGenerator

```java
keyGen.init(secureRandom);
```

## 生成密钥

```java
Key key = keyGen.generateKey();
```

## 使用密钥初始化Mac对象

```java
Mac mac = Mac.getInstance("HmacMD5");
mac.init(key);
```

> `Mac`支持以下类型：
>
> - HmacMD5
> - HmacSHA1
> - HmacSHA256

## 完成mac操作

```java
String msg = "gcdd1993";
byte[] bytes = msg.getBytes();
byte[] macResult = mac.doFinal(bytes);
```

# 数字签名

> 数字签名允许验证签名的作者，日期和时间，验证消息内容。 它还包括用于其他功能的身份验证功能。

![](https://i.loli.net/2019/04/10/5cade8c25ab4c.png)

## 优点

- 认证

  > 数字签名有助于验证消息来源。 

- 完整性

  > 邮件签名后，邮件中的任何更改都将使签名无效。

- 不可否认

  > 通过此属性，任何已签署某些信息的实体都不能在以后拒绝签名。

## 创建数字签名

### 创建KeyPairGenerator对象

> `KeyPairGenerator`类提供`getInstance()`方法，该方法接受表示所需密钥生成算法的String变量，并返回生成密钥的`KeyPairGenerator`对象。

```java
KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
```

### 初始化KeyPairGenerator对象

> `KeyPairGenerator`类提供了一个名为`initialize()`的方法，该方法用于初始化密钥对生成器。 此方法接受表示密钥大小的整数值。

```java
keyPairGen.initialize(2048);
```

### 生成KeyPair

> 使用`generateKeyPair()`方法生成密钥对

```java
KeyPair pair = keyPairGen.generateKeyPair();
```

### 从密钥对中获取私钥

```java
PrivateKey privateKey = pair.getPrivate();
```

### 创建签名对象

> `Signature`类的`getInstance()`方法接受表示所需签名算法的字符串参数，并返回相应的`Signature`对象。
>
> Signature支持以下类型：
>
> - SHA1withDSA
> - SHA1withRSA
> - SHA256withRSA

```java
Signature sign = Signature.getInstance("SHA256withDSA");
```

### 初始化签名对象

```java
sign.initSign(privateKey);
```

### 将数据添加到Signature对象

```java
String msg = "gcdd1993";
sign.update(msg.getBytes());
```

### 计算签名

```java
byte[] signature = sign.sign();
```

## 验证签名

> 我们创建签名后，通常可以将私钥发送到客户端，以进行签名操作。服务端保存公钥，以进行签名验证

### 初始化签名对象以进行验证

> 使用公钥初始化签名对象

```java
sign.initVerify(pair.getPublic());
```

### 更新要验证的数据

```java
sign.update(msg.getBytes());
```

### 验证签名

```java
boolean verify = sign.verify(signature);
Assert.assertTrue(verify);
```

# 公私钥加解密数据

> 可以使用`javax.crypto`包的Cipher类加密给定数据。 

获取公私钥的步骤，与签名类似

```java
KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
keyPairGen.initialize(2048);
KeyPair pair = keyPairGen.generateKeyPair();
PublicKey publicKey = pair.getPublic();
```

## 加密数据

### 创建一个Cipher对象

> `Cipher`类的`getInstance()`方法接受表示所需转换的String变量，并返回实现给定转换的`Cipher`对象。
>
> Cipher支持以下类型：
>
> - AES/CBC/NoPadding (128)
> - AES/CBC/PKCS5Padding (128)
> - AES/ECB/NoPadding (128)
> - AES/ECB/PKCS5Padding (128)
> - DES/CBC/NoPadding (56)
> - DES/CBC/PKCS5Padding (56)
> - DES/ECB/NoPadding (56)
> - DES/ECB/PKCS5Padding (56)
> - DESede/CBC/NoPadding (168)
> - DESede/CBC/PKCS5Padding (168)
> - DESede/ECB/NoPadding (168)
> - DESede/ECB/PKCS5Padding (168)
> - RSA/ECB/PKCS1Padding (1024, 2048)
> - RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)
> - RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048)

```java
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
```

### 使用公钥初始化Cipher对象

> `Cipher`类的`init()`方法接受两个参数，一个表示操作模式的整数参数(加密/解密)和一个表示公钥的Key对象。

```java
cipher.init(Cipher.ENCRYPT_MODE, publicKey);
```

### 将数据添加到Cipher对象

> `Cipher`类的`update()`方法接受表示要加密的数据的字节数组，并使用给定的数据更新当前对象。

```java
String msg = "gcdd1993";
cipher.update(msg.getBytes());
```

### 加密数据

```java
byte[] cipherText = cipher.doFinal();
```

## 解密数据

### 使用私钥初始化Cipher对象

```java
cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
```

### 解密数据

```java
byte[] decipheredText = cipher.doFinal(cipherText);
Assert.assertEquals(msg, new String(decipheredText));
```

# 第三方类库

> 前后端适用且应用广泛的是[`Crypto-JS`](<https://github.com/brix/crypto-js>),使用 `Crypto-JS `可以非常方便地在 JavaScript 进行 MD5、SHA1、SHA2、SHA3、RIPEMD-160 哈希散列，进行 AES、DES、Rabbit、RC4、Triple DES 加解密。

## AES加密

> **高级加密标准**（英语：**A**dvanced **E**ncryption **S**tandard，缩写：[AES](<https://zh.wikipedia.org/wiki/%E9%AB%98%E7%BA%A7%E5%8A%A0%E5%AF%86%E6%A0%87%E5%87%86>)），在密码学中又称**Rijndael加密法**，是美国联邦政府采用的一种[区块加密](https://zh.wikipedia.org/wiki/%E5%8D%80%E5%A1%8A%E5%8A%A0%E5%AF%86)标准。这个标准用来替代原先的[DES](https://zh.wikipedia.org/wiki/DES)，已经被多方分析且广为全世界所使用。

一般来说，我们可以在服务端随机生成密钥，然后将密钥发送给客户端进行加密，上传密文到服务端，服务端进行解密。

本文只讨论Java的AES加解密方式。

### 引入Jar包

```
compile group: 'org.webjars.npm', name: 'crypto-js', version: '3.1.8'
```

### 生成密钥

```java
Random random = new Random();
byte[] key = new byte[16];
random.nextBytes(key);
SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
```

### 生成偏移量

```java
byte[] iv = new byte[16];
random.nextBytes(iv);
IvParameterSpec ivSpec = new IvParameterSpec(iv);
```

### 创建Cipher对象

```java
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
```

### 初始化Cipher为加密工作过程

```java
cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
```

### 加密

```java
byte[] original = cipher.doFinal(encrypted1);
```

## AES解密

### 初始化Cipher为解密工作过程

```java
cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
```

### 解密

```java
byte[] bytes = cipher.doFinal(original);
Assert.assertEquals(data, new String(bytes, StandardCharsets.UTF_8));
```

## AES加解密总结

实际项目中，可以按照以下方式实现对称加密

1. 服务端提供一个接口，该接口负责随机生成key（密码）和iv（偏移量），并将其存入redis（设置超时时间）
2. 客户端调用接口，获得key和iv以及一个redis_key，进行数据加密，将加密后的数据以及redis_key传到服务端
3. 服务端使用redis_key获得key和iv，进行解密

# 总结

在Java EE安全里，主要是进行客户端加密，以及服务端解密的过程来实现数据安全传输的目的。在这个过程中，特别要注意以下几点：

- 随机性：加密方式不可单一，可通过更换`Cipher.getInstance()`的String值来随机生成加密工人进行加密。
- 保密性：加密使用的密钥或者偏移量等，需要使用超时、模糊目的等手段进行隐藏，加大破解成本。

没有完全有效的加密，但是只要做到破解成本大于加密成本，就是有效的加密。这样，我们可以不断地更换加密方式达到我们想要的效果。
