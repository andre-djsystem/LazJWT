# LazJWT
Lazarus  implementation of JWT - https://jwt.io/

#### Claims

| _Algorithms_ | _Supported_      | 
| -------------| -----------      |
|  `iss`       | ✔️               |
|  `sub`       | ✔️               |
|  `aud`       | ✔️               |
|  `exp`       | ✔️               |
|  `nbf`       | ✔️               |
|  `iat`       | ✔️               |
|  `jti`       | ✔️               |

#### Signing algorithms
| _Algorithms_ | _Supported_  | 
| -------------| -----------  |
|  `HS256`     | ✔️           |
|  `HS384`     | ✔️           |
|  `HS512`     | ✔️           |
|  `RS256`     | ❌           |
|  `RS384`     | ❌           |
|  `RS512`     | ❌           |
|  `ES256`     | ❌           |
|  `ES384`     | ❌           |
|  `ES512`     | ❌           |
|  `ES256K`    | ❌           |

## ⭕ Prerequisites
- [**hashlib4pascal**](https://github.com/andre-djsystem/hashlib4pascal) - is an Object Pascal hashing library released under the permissive MIT License which provides an easy to use interface for computing hashes and checksums of data. It also supports state based (incremental) hashing.

## ⚙️ Installation
Installation is done using the [`boss install`](https://github.com/HashLoad/boss) command:

``` sh
boss install https://github.com/andre-djsystem/LazJWT
```

### Manual installation
If you choose to install manually, simply add the following folders to your project, in *Project > Project Options > Paths > Other unit files (-Fu) > Include file search path*
```
../LazJWT/src
../HashLib/src/Base
../HashLib/src/Checksum
../HashLib/src/Crypto
../HashLib/src/Hash128
../HashLib/src/Hash32
../HashLib/src/Hash64
../HashLib/src/Include
../HashLib/src/Interfaces
../HashLib/src/KDF
../HashLib/src/NullDigest
../HashLib/src/Nullable
../HashLib/src/Packages
../HashLib/src/Utils
```

## ⚡️ Quickstart

#### Creating a token

- With default Claims

```delphi
uses
  LazJWT;
  
var
  LResult: String;
begin
  LResult := TLazJWT
               .New
               .SecretJWT('your-256-bit-secret')
               .Iss('1234567890')
               .Sub('1234567890')
               .Aud('123456')
               .Exp(1516239022)
               .Nbf(1516239022)
               .Iat(1516239022)
               .JTI('123456')
               .Token; 
end;   

```

- With Custom Claims

```delphi
uses
  LazJWT;
  
var
  LResult: String;
begin
  LResult := TLazJWT
               .New
               .SecretJWT('your-256-bit-secret')
               .Iss('1234567890')
               .Sub('1234567890')
               .Aud('123456')
               .Exp(1516239022)
               .Nbf(1516239022)
               .Iat(1516239022)
               .JTI('123456')
               .AddClaim('Validated', True)
               .AddClaim('Name', 'Andre')  
               .AddClaim('Level', 10)  
               .AddClaim('Limit', 100.00) 
               .Token; 
end;   

```


- Custom PayLoad

```delphi
uses
  LazJWT;
  
var
  LCustomPayLoad: TJSONData;
  LResult: String;
begin
  LCustomPayLoad := GetJSON('{"Fld1" : "Hello", "Fld2" : 42, "Colors" : ["Red", "Green", "Blue"]}');
  LResult := TLazJWT
               .New
               .SecretJWT('your-256-bit-secret')
               .CustomPayLoad(LCustomPayLoad)
               .Token;
end;   

```

#### Validating a token

**Note**: With Custom PayLoad, only signature is validate

```delphi
uses
  LazJWT;
  
var
  LResult: String;
begin
  try
    TLazJWT
      .New
      .UseCustomPayLoad(False) //Set before Token
      .Token('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')
      .SecretJWT('your-256-bit-secret')
      .ValidateToken;
    LResult := 'Token Verified';
  except
    On E: Exception do
    begin
      LResult := E.Message;
    end;
  end;
end;  

```

#### Config Validations

```delphi
uses
  LazJWT;
  
var
  LResult: String;
begin
  try
    TLazJWT
      .New(TLazJWTConfig
             .New
             .IsRequiredSubject(False)
             .IsRequiredIssuedAt(False)
             .IsRequiredNotBefore(False)
             .IsRequiredExpirationTime(False)
             .IsRequireAudience(True)
             .ExpectedAudience(['lazarus','djsystem'])
             ) 
      .UseCustomPayLoad(False) //Set before Token
      .Token('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')
      .SecretJWT('your-256-bit-secret')
      .ValidateToken;
    LResult := 'Token Verified';
  except
    On E: Exception do
    begin
      LResult := E.Message;
    end;
  end;
end;  

```

Inspired in [Delphi JOSE and JWT Library](https://github.com/paolo-rossi/delphi-jose-jwt#delphi-jose-and-jwt-library)

## ⚠️ License
`LazJWT` is free and open-source library licensed under the [MIT License](https://github.com/andre-djsystem/LazJWT/blob/main/LICENSE).
