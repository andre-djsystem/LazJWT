unit LazJWT;

{$MODE DELPHI}{$H+}

interface

uses
  Generics.Collections, Classes, SysUtils, StrUtils, DateUtils,
  fpjwt, fpjson, Base64, HlpIHashInfo, HlpConverters, HlpHashFactory;

type
  ILazJWTConfig = interface
  ['{3B6CAB90-3620-494F-9C9F-F809FFE75075}']
     function IsRequiredSubject: Boolean; overload;
     function IsRequiredSubject(const AValue: Boolean): ILazJWTConfig; overload;
     function IsRequiredIssuedAt: Boolean; overload;
     function IsRequiredIssuedAt(const AValue: Boolean): ILazJWTConfig; overload;
     function IsRequiredNotBefore: Boolean; overload;
     function IsRequiredNotBefore(const AValue: Boolean): ILazJWTConfig; overload;
     function IsRequiredExpirationTime: Boolean; overload;
     function IsRequiredExpirationTime(const AValue: Boolean): ILazJWTConfig; overload;
     function IsRequireAudience: Boolean; overload;
     function IsRequireAudience(const AValue: Boolean): ILazJWTConfig; overload;
     function ExpectedAudience: TArray<string>; overload;
     function ExpectedAudience(const AValue: TArray<string>): ILazJWTConfig; overload;
  end;

  { TLazJWTConfig }

  TLazJWTConfig = class(TInterfacedObject, ILazJWTConfig)
  private
    FIsRequireAudience: Boolean;
    FExpectedAudience: TArray<string>;
    FIsRequiredExpirationTime: Boolean;
    FIsRequiredIssuedAt: Boolean;
    FIsRequiredNotBefore: Boolean;
    FIsRequiredSubject: Boolean;
    function IsRequiredSubject: Boolean; overload;
    function IsRequiredSubject(const AValue: Boolean): ILazJWTConfig; overload;
    function IsRequiredIssuedAt: Boolean; overload;
    function IsRequiredIssuedAt(const AValue: Boolean): ILazJWTConfig; overload;
    function IsRequiredNotBefore: Boolean; overload;
    function IsRequiredNotBefore(const AValue: Boolean): ILazJWTConfig; overload;
    function IsRequiredExpirationTime: Boolean; overload;
    function IsRequiredExpirationTime(const AValue: Boolean): ILazJWTConfig; overload;
    function IsRequireAudience: Boolean; overload;
    function IsRequireAudience(const AValue: Boolean): ILazJWTConfig; overload;
    function ExpectedAudience: TArray<string>; overload;
    function ExpectedAudience(const AValue: TArray<string>): ILazJWTConfig; overload;
  public
    constructor Create;
    class function New: ILazJWTConfig;
  end;

  { ILazJWT }

  ILazJWT = interface
  ['{02D099BA-321F-4193-9F70-40F9614777C4}']
    function SecretJWT: String; overload;
    function SecretJWT(const AValue: String): ILazJWT; overload;
    function Alg: String; overload;
    function Alg(const AValue: String): ILazJWT; overload;
    function Typ: String; overload;
    function Typ(const AValue: String): ILazJWT; overload;
    function Iss: String; overload;
    function Iss(const AValue: String): ILazJWT; overload;
    function Sub: String; overload;
    function Sub(const AValue: String): ILazJWT; overload;
    function Aud: String; overload;
    function Aud(const AValue: String): ILazJWT; overload;
    function Exp: Int64; overload;
    function Exp(const AValue: Int64): ILazJWT; overload;
    function Nbf: Int64; overload;
    function Nbf(const AValue: Int64): ILazJWT; overload;
    function Iat: Int64; overload;
    function Iat(const AValue: Int64): ILazJWT; overload;
    function JTI: String; overload;
    function JTI(const AValue: String): ILazJWT; overload;
    function Token: String; overload;
    function Token(const AValue: String): ILazJWT; overload;
    function CustomPayLoad: TJSONData; overload;
    function CustomPayLoad(const AValue: TJSONData): ILazJWT; overload;
    function UseCustomPayLoad: Boolean; overload;
    function UseCustomPayLoad(const AValue: Boolean): ILazJWT; overload;
    function CustomClaims: TJSONObject; overload;
    function CustomClaims(const AValue: TJSONObject; const AFreeObject: Boolean = True): ILazJWT; overload;
    function AddClaim(const AName: String; AValue: TJSONData; const AFreeObject: Boolean = True): ILazJWT; overload;
    function AddClaim(const AName: String; AValue: Boolean): ILazJWT; overload;
    function AddClaim(const AName: String; AValue: TJSONFloat): ILazJWT; overload;
    function AddClaim(const AName, AValue: String): ILazJWT; overload;
    function AddClaim(const AName : String; AValue: TJSONUnicodeStringType): ILazJWT; overload;
    function AddClaim(const AName: String; Avalue: Int64): ILazJWT; overload;
    function AddClaim(const AName: String; Avalue: QWord): ILazJWT; overload;
    function AddClaim(const AName: String; Avalue: Integer): ILazJWT; overload;
    function AddClaim(const AName: String; AValue : TJSONArray; const AFreeObject: Boolean = True): ILazJWT; overload;
    function Header: String;
    function PayLoad: String;
    function AsString: String;
    function ValidateSignature: Boolean;
    procedure ValidateToken;
  end;

  { TLazJWT }
  TLazJWT = class(TInterfacedObject, ILazJWT)
  strict private
    function HexToAscii(const HexStr: String): AnsiString;
    function CalcSignature(const AToken: String): String;
    function GetHeader: String;
    function GetHeaderEncoded: String;
    procedure SetHeader(const AToken: String);
    function GetPayLoad: String;
    function GetPayLoadEncoded: String;
    procedure SetPayLoad(const AToken: String);
    procedure SetSignature(const AToken: String);
  private
    FJWT: TJWT;
    FSecretJWT: String;
    FToken: String;
    FSignature: String;
    FAlg: String;
    FType: String;
    FAud: String;
    FExp: Int64;
    FIat: Int64;
    FIss: String;
    FJTI: String;
    FNbf: Int64;
    FSub: String;
    FCustomPayLoad: TJSONData;
    FUseCustomPayLoad: Boolean;
    FLazJWTConfig: ILazJWTConfig;
    FCustomClaims: TJSONObject;

    function SecretJWT: String; overload;
    function SecretJWT(const AValue: String): ILazJWT; overload;
    function Alg: String; overload;
    function Alg(const AValue: String): ILazJWT; overload;
    function Typ: String; overload;
    function Typ(const AValue: String): ILazJWT; overload;
    function Iss: String; overload;
    function Iss(const AValue: String): ILazJWT; overload;
    function Sub: String; overload;
    function Sub(const AValue: String): ILazJWT; overload;
    function Aud: String; overload;
    function Aud(const AValue: String): ILazJWT; overload;
    function Exp: Int64; overload;
    function Exp(const AValue: Int64): ILazJWT; overload;
    function Nbf: Int64; overload;
    function Nbf(const AValue: Int64): ILazJWT; overload;
    function Iat: Int64; overload;
    function Iat(const AValue: Int64): ILazJWT; overload;
    function JTI: String; overload;
    function JTI(const AValue: String): ILazJWT; overload;
    function Token: String; overload;
    function Token(const AValue: String): ILazJWT; overload;
    function CustomPayLoad: TJSONData; overload;
    function CustomPayLoad(const AValue: TJSONData): ILazJWT; overload;
    function UseCustomPayLoad: Boolean; overload;
    function UseCustomPayLoad(const AValue: Boolean): ILazJWT; overload;
    function CustomClaims: TJSONObject; overload;
    function CustomClaims(const AValue: TJSONObject; const AFreeObject: Boolean = True): ILazJWT; overload;
    function AddClaim(const AName: String; AValue: TJSONData; const AFreeObject: Boolean = True): ILazJWT; overload;
    function AddClaim(const AName: String; AValue: Boolean): ILazJWT; overload;
    function AddClaim(const AName: String; AValue: TJSONFloat): ILazJWT; overload;
    function AddClaim(const AName, AValue: String): ILazJWT; overload;
    function AddClaim(const AName : String; AValue: TJSONUnicodeStringType): ILazJWT; overload;
    function AddClaim(const AName: String; Avalue: Int64): ILazJWT; overload;
    function AddClaim(const AName: String; Avalue: QWord): ILazJWT; overload;
    function AddClaim(const AName: String; Avalue: Integer): ILazJWT; overload;
    function AddClaim(const AName: String; AValue : TJSONArray; const AFreeObject: Boolean = True): ILazJWT; overload;
    function Header: String;
    function PayLoad: String;
    function AsString: String;
    function ValidateSignature: Boolean;
    procedure ValidateToken;
  public
    constructor Create(AConfig: ILazJWTConfig = nil);
    destructor Destroy; override;
    class function New(AConfig: ILazJWTConfig = nil): ILazJWT;
  end;

implementation

{ TLazJWTConfig }

function TLazJWTConfig.IsRequiredSubject: Boolean;
begin
 Result := FIsRequiredSubject;
end;

function TLazJWTConfig.IsRequiredSubject(const AValue: Boolean): ILazJWTConfig;
begin
 FIsRequiredSubject := AValue;
 Result := Self;
end;

function TLazJWTConfig.IsRequiredIssuedAt: Boolean;
begin
 Result := FIsRequiredIssuedAt;
end;

function TLazJWTConfig.IsRequiredIssuedAt(const AValue: Boolean): ILazJWTConfig;
begin
 FIsRequiredIssuedAt := AValue;
 Result := Self;
end;

function TLazJWTConfig.IsRequiredNotBefore: Boolean;
begin
 Result := FIsRequiredNotBefore;
end;

function TLazJWTConfig.IsRequiredNotBefore(const AValue: Boolean
  ): ILazJWTConfig;
begin
 FIsRequiredNotBefore := AValue;
 Result := Self;
end;

function TLazJWTConfig.IsRequiredExpirationTime: Boolean;
begin
 Result := FIsRequiredExpirationTime;
end;

function TLazJWTConfig.IsRequiredExpirationTime(const AValue: Boolean
  ): ILazJWTConfig;
begin
 FIsRequiredExpirationTime := AValue;
 Result := Self;
end;

function TLazJWTConfig.IsRequireAudience: Boolean;
begin
 Result := FIsRequireAudience;
end;

function TLazJWTConfig.IsRequireAudience(const AValue: Boolean): ILazJWTConfig;
begin
 FIsRequireAudience := AValue;
 Result := Self;
end;

function TLazJWTConfig.ExpectedAudience: TArray<string>;
begin
 Result := FExpectedAudience;
end;

function TLazJWTConfig.ExpectedAudience(const AValue: TArray<string>
  ): ILazJWTConfig;
begin
 FExpectedAudience := AValue;
 Result := Self;
end;

constructor TLazJWTConfig.Create;
begin
 FIsRequireAudience := False;
 FIsRequiredExpirationTime := False;
 FIsRequiredIssuedAt := False;
 FIsRequiredNotBefore := False;
 FIsRequiredSubject := False;
end;

class function TLazJWTConfig.New: ILazJWTConfig;
begin
 Result := Self.Create;
end;

{ TLazJWT }

function TLazJWT.HexToAscii(const HexStr: String): AnsiString;
var
  B: Byte;
  Cmd: string;
  I, L: Integer;
begin
  Result := '';
  Cmd := Trim(HexStr);
  I := 1;
  L := Length(Cmd);

  while I < L do
  begin
     B := StrToInt('$' + copy(Cmd, I, 2));
     Result := Result + AnsiChar(chr(B));
     Inc( I, 2);
  end;
end;

function TLazJWT.CalcSignature(const AToken: String): String;
var
  LHMAC: IHMAC = nil;
  LSignCalc: String = '';
  LToken: String = '';
begin
  case AnsiIndexText(UpperCase(FAlg), ['HS256', 'HS384', 'HS512']) of
    0: LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_256);
    1: LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_384);
    2: LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_512);
  else
    raise Exception.Create('[alg] not implemented');
  end;

  LToken := Trim(AToken);
  LHMAC.Key := TConverters.ConvertStringToBytes(UTF8Encode(FSecretJWT), TEncoding.UTF8);
  LSignCalc := HexToAscii(TConverters.ConvertBytesToHexString(LHMAC.ComputeString(UTF8Encode(LToken), TEncoding.UTF8).GetBytes,False));
  LSignCalc := FJWT.Base64ToBase64URL(EncodeStringBase64(LSignCalc));

  Result := LSignCalc;
end;

function TLazJWT.GetHeader: String;
begin
  Result := Format('{"alg": "%s", "typ": "%s"}',[FAlg,FType]);
end;

function TLazJWT.GetHeaderEncoded: String;
begin
  Result := FJWT.Base64ToBase64URL(EncodeStringBase64(GetHeader));
end;

procedure TLazJWT.SetHeader(const AToken: String);
var
  LHeader: TJSONObject = nil;
  LHeaderStr: String = '';
begin
  if (AToken = EmptyStr) then
    Exit;

  try
    LHeaderStr :=  FJWT.DecodeString(Copy(AToken, 0, Pos('.',AToken)-1));
    LHeader := TJSONObject(GetJSON(LHeaderStr));
    try
      if Assigned(LHeader.FindPath('alg')) then
        FAlg := LHeader.FindPath('alg').AsString;
      if Assigned(LHeader.FindPath('typ')) then
        FType := LHeader.FindPath('typ').AsString;
    finally
      LHeader.Free;
    end;
  except
    raise Exception.Create('Invalid Header');
  end;
end;

function TLazJWT.GetPayLoad: String;
var
  LPayLoad: TJSONObject = nil;
  I: Integer;
begin
 if Assigned(FCustomPayLoad) then
   Result := FCustomPayLoad.AsJSON
 else
 begin
   LPayLoad := TJSONObject.Create;
   try
     if (FIss <> EmptyStr) then
       LPayLoad.Add('iss', FIss);
     if (FSub <> EmptyStr) then
       LPayLoad.Add('sub', FSub);
     if (FAud <> EmptyStr) then
       LPayLoad.Add('aud', FAud);
     if (FExp > 0) then
       LPayLoad.Add('exp', FExp);
     if (FNbf > 0) then
       LPayLoad.Add('nbf', FNbf);
     if (FIat > 0) then
       LPayLoad.Add('iat', FIat);
     if (FJTI <> EmptyStr) then
       LPayLoad.Add('jti', FJTI);

     for I:=0 to Pred(FCustomClaims.Count) do
     begin
       LPayLoad.Add(FCustomClaims.Names[I],FCustomClaims.Items[I].Clone);
     end;

     Result := LPayLoad.AsJSON;
   finally
     LPayLoad.Free;
   end;
 end;
end;

function TLazJWT.GetPayLoadEncoded: String;
begin
  Result := FJWT.Base64ToBase64URL(EncodeStringBase64(GetPayLoad));
end;

procedure TLazJWT.SetPayLoad(const AToken: String);
var
  LPayLoad: TJSONObject = nil;
  LPayLoadStr: String = '';
  PosIni, PosEnd: Integer;
begin
 if (AToken = EmptyStr) then
   Exit;

 try
   PosIni := Pos('.',AToken)+1;
   PosEnd := NPos('.',AToken,2)-PosIni;
   LPayLoadStr := Copy(AToken, PosIni, PosEnd);

   LPayLoadStr := FJWT.DecodeString(LPayLoadStr);

    if FUseCustomPayLoad then
      FCustomPayLoad := GetJSON(LPayLoadStr)
    else
    begin
      LPayLoad := TJSONObject(GetJSON(LPayLoadStr));
      try
        if Assigned(LPayLoad.FindPath('iss')) then
        begin
          FIss := LPayLoad.FindPath('iss').AsString;
          LPayLoad.Delete('iss');
        end;
        if Assigned(LPayLoad.FindPath('sub')) then
        begin
          FSub := LPayLoad.FindPath('sub').AsString;
          LPayLoad.Delete('sub');
        end;
        if Assigned(LPayLoad.FindPath('aud')) then
        begin
          FAud := LPayLoad.FindPath('aud').AsString;
          LPayLoad.Delete('aud');
        end;
        if Assigned(LPayLoad.FindPath('exp')) then
        begin
          FExp := LPayLoad.FindPath('exp').AsInt64;
          LPayLoad.Delete('exp');
        end;
        if Assigned(LPayLoad.FindPath('nbf')) then
        begin
          FNbf := LPayLoad.FindPath('nbf').AsInt64;
          LPayLoad.Delete('nbf');
        end;
        if Assigned(LPayLoad.FindPath('iat')) then
        begin
          FIat := LPayLoad.FindPath('iat').AsInt64;
          LPayLoad.Delete('iat');
        end;
        if Assigned(LPayLoad.FindPath('jti')) then
        begin
          FJTI := LPayLoad.FindPath('jti').AsString;
          LPayLoad.Delete('jti');
        end;

        if (LPayLoad.Count > 0) then
          CustomClaims(LPayLoad, False);
      finally
        LPayLoad.Free;
      end;
    end;
 except
   raise Exception.Create('Invalid Payload');
 end;
end;

procedure TLazJWT.SetSignature(const AToken: String);
var
  PosIni: Integer;
begin
  PosIni := NPos('.',AToken,2)+1;
  FSignature := Copy(AToken, PosIni);
end;

function TLazJWT.SecretJWT: String;
begin
  Result := FSecretJWT;
end;

function TLazJWT.SecretJWT(const AValue: String): ILazJWT;
begin
  FSecretJWT := AValue;
  Result := Self;
end;

function TLazJWT.Alg: String;
begin
  Result := FAlg;
end;

function TLazJWT.Alg(const AValue: String): ILazJWT;
begin
  FAlg := AValue;
  Result := Self;
end;

function TLazJWT.Typ: String;
begin
 Result := FType;
end;

function TLazJWT.Typ(const AValue: String): ILazJWT;
begin
 FType := AValue;
 Result := Self;
end;

function TLazJWT.Iss: String;
begin
  Result := FIss;
end;

function TLazJWT.Iss(const AValue: String): ILazJWT;
begin
  FIss := AValue;
  Result := Self;
end;

function TLazJWT.Sub: String;
begin
  Result := FSub;
end;

function TLazJWT.Sub(const AValue: String): ILazJWT;
begin
  FSub := AValue;
  Result := Self;
end;

function TLazJWT.Aud: String;
begin
  Result := FAud;
end;

function TLazJWT.Aud(const AValue: String): ILazJWT;
begin
  FAud := AValue;
  Result := Self;
end;

function TLazJWT.Exp: Int64;
begin
  Result := FExp;
end;

function TLazJWT.Exp(const AValue: Int64): ILazJWT;
begin
  FExp := AValue;
  Result := Self;
end;

function TLazJWT.Nbf: Int64;
begin
  Result := FNbf;
end;

function TLazJWT.Nbf(const AValue: Int64): ILazJWT;
begin
  FNbf := AValue;
  Result := Self;
end;

function TLazJWT.Iat: Int64;
begin
  Result := FIat;
end;

function TLazJWT.Iat(const AValue: Int64): ILazJWT;
begin
  FIat := AValue;
  Result := Self;
end;

function TLazJWT.JTI: String;
begin
  Result := FJTI;
end;

function TLazJWT.JTI(const AValue: String): ILazJWT;
begin
  FJTI := AValue;
  Result := Self;
end;

function TLazJWT.Token: String;
var
  LToken: String;
begin
  LToken := GetHeaderEncoded + '.' + GetPayLoadEncoded;

  FSignature := CalcSignature(LToken);

  Result := AsString;
end;

function TLazJWT.Token(const AValue: String): ILazJWT;
begin
  FToken := AValue;
  SetHeader(FToken);
  SetPayLoad(FToken);
  SetSignature(FToken);
  Result := Self;
end;

function TLazJWT.CustomPayLoad: TJSONData;
begin
  Result := Nil;
  if Assigned(FCustomPayLoad) then
    Result := FCustomPayLoad;
end;

function TLazJWT.CustomPayLoad(const AValue: TJSONData): ILazJWT;
begin
  FCustomPayLoad := AValue;
  FUseCustomPayLoad := True;
  Result := Self;
end;

function TLazJWT.UseCustomPayLoad: Boolean;
begin
  Result := FUseCustomPayLoad;
end;

function TLazJWT.UseCustomPayLoad(const AValue: Boolean): ILazJWT;
begin
  FUseCustomPayLoad := AValue;
  Result := Self;
end;

function TLazJWT.CustomClaims: TJSONObject;
begin
 Result := FCustomClaims;
end;

function TLazJWT.CustomClaims(const AValue: TJSONObject; const AFreeObject: Boolean): ILazJWT;
var
  I: Integer;
begin
 Result := Self;
 for I:=0 to Pred(AValue.Count) do
 begin
   FCustomClaims.Add(AValue.Names[I],AValue.Items[I].Clone);
 end;
 if AFreeObject then
   AValue.Free;
end;

function TLazJWT.AddClaim(const AName: String; AValue: TJSONData; const AFreeObject: Boolean): ILazJWT;
begin
 Result := Self;
 FCustomClaims.Add(AName,AValue.Clone);
 if AFreeObject then
   AValue.Free;
end;

function TLazJWT.AddClaim(const AName: String; AValue: Boolean): ILazJWT;
begin
 Result := Self;
 FCustomClaims.Add(AName,AValue);
end;

function TLazJWT.AddClaim(const AName: String; AValue: TJSONFloat): ILazJWT;
begin
 Result := Self;
 FCustomClaims.Add(AName,AValue);
end;

function TLazJWT.AddClaim(const AName, AValue: String): ILazJWT;
begin
 Result := Self;
 FCustomClaims.Add(AName,AValue);
end;

function TLazJWT.AddClaim(const AName: String; AValue: TJSONUnicodeStringType
  ): ILazJWT;
begin
 Result := Self;
 FCustomClaims.Add(AName,AValue);
end;

function TLazJWT.AddClaim(const AName: String; Avalue: Int64): ILazJWT;
begin
 Result := Self;
 FCustomClaims.Add(AName,AValue);
end;

function TLazJWT.AddClaim(const AName: String; Avalue: QWord): ILazJWT;
begin
 Result := Self;
 FCustomClaims.Add(AName,AValue);
end;

function TLazJWT.AddClaim(const AName: String; Avalue: Integer): ILazJWT;
begin
 Result := Self;
 FCustomClaims.Add(AName,AValue);
end;

function TLazJWT.AddClaim(const AName: String; AValue: TJSONArray; const AFreeObject: Boolean): ILazJWT;
begin
 Result := Self;
 FCustomClaims.Add(AName,AValue.Clone);
 if AFreeObject then
   AValue.Free;
end;

function TLazJWT.Header: String;
begin
  Result := GetHeader;
end;

function TLazJWT.PayLoad: String;
begin
  Result := GetPayLoad;
end;

function TLazJWT.AsString: String;
begin
  Result := GetHeaderEncoded + '.' + GetPayLoadEncoded;
  if (FSignature <> EmptyStr) then
    Result :=  Result + '.' + FSignature;
end;

function TLazJWT.ValidateSignature: Boolean;
begin
  Result := ( FSignature = CalcSignature(GetHeaderEncoded + '.' + GetPayLoadEncoded));
end;

procedure TLazJWT.ValidateToken;
begin
  if not ValidateSignature then
    raise  Exception.Create('Invalid Signature');

  if not FUseCustomPayLoad then
  begin
    if (FExp <> 0) and (FExp < DateTimeToUnix(Now, False)) then
      raise  Exception.Create(Format(
            'The JWT is no longer valid - the evaluation time [%s] is on or after the Expiration Time [exp=%s]',
            [DateToISO8601(Now, False), DateToISO8601(FExp, False)]));

    if (FNbf <> 0) and (FNbf < DateTimeToUnix(Now, false)) then
      raise  Exception.Create(Format('The JWT is not yet valid as the evaluation time [%s] is before the NotBefore [nbf=%s]',
            [DateToISO8601(Now, False), DateToISO8601(FNbf)]));

    if Assigned(FLazJWTConfig) then
    begin
      if FLazJWTConfig.IsRequireAudience and ((FAud) = EmptyStr) then
        raise  Exception.Create('No Audience [aud] claim present');

      if (Length(FLazJWTConfig.ExpectedAudience)>0) and (not MatchText(FAud, FLazJWTConfig.ExpectedAudience)) then
        raise  Exception.Create('Audience [aud] claim present in the JWT but no expected audience value(s) were provided');

      if FLazJWTConfig.IsRequiredExpirationTime and ((FExp) = 0) then
        raise  Exception.Create('No Expiration Time [exp] claim present');

      if FLazJWTConfig.IsRequiredIssuedAt and ((FIat) = 0) then
        raise  Exception.Create('No IssuedAt [iat] claim present');

      if FLazJWTConfig.IsRequiredNotBefore and ((FNbf) = 0) then
        raise  Exception.Create('No NotBefore [nbf] claim present');

      if FLazJWTConfig.IsRequiredSubject and ((FSub) = EmptyStr) then
        raise  Exception.Create('No Subject [sub] claim present');
    end;
  end;
end;

constructor TLazJWT.Create(AConfig: ILazJWTConfig);
begin
  FJWT := TJWT.Create;
  FCustomClaims := TJSONObject.Create;
  FAlg := 'HS256';
  FType := 'JWT';
  FIss := EmptyStr;
  FSub := EmptyStr;
  FAud := EmptyStr;
  FExp := 0;
  FNbf := 0;
  FIat := 0;
  FJTI := EmptyStr;
  FCustomPayLoad := nil;
  FUseCustomPayLoad := False;
  FLazJWTConfig := AConfig;
  if not Assigned(AConfig) then
    FLazJWTConfig := TLazJWTConfig.New;
end;

destructor TLazJWT.Destroy;
begin
  if Assigned(FCustomPayLoad) then
    FreeAndNil(FCustomPayLoad);

  FreeAndNil(FCustomClaims);
  FreeAndNil(FJWT);
  inherited Destroy;
end;

class function TLazJWT.New(AConfig: ILazJWTConfig): ILazJWT;
begin
  Result := Self.Create(AConfig);
end;

end.
